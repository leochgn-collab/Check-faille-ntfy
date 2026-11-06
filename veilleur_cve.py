#!/usr/bin/env python3
"""
Veilleur CVE -> ntfy
Interroge l'API NVD (NIST) en boucle et envoie chaque nouvelle faille
sur un topic ntfy, avec une priorité qui dépend de sa gravité CVSS.

Aucune dépendance externe : uniquement la bibliothèque standard Python.
"""

import json
import os
import sys
import time
import signal
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Configuration (variables d'environnement)
# --------------------------------------------------------------------------
NTFY_URL = os.getenv("NTFY_URL", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "")
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "")          # token d'accès ntfy (optionnel)
NTFY_USER = os.getenv("NTFY_USER", "")            # ou user / mot de passe (optionnel)
NTFY_PASSWORD = os.getenv("NTFY_PASSWORD", "")

NVD_API_KEY = os.getenv("NVD_API_KEY", "")        # gratuite, fortement conseillée
CHECK_INTERVAL_MIN = int(os.getenv("CHECK_INTERVAL_MIN", "15"))
MIN_SEVERITY = os.getenv("MIN_SEVERITY", "NONE").upper()   # NONE|LOW|MEDIUM|HIGH|CRITICAL
KEYWORDS = [k.strip().lower() for k in os.getenv("KEYWORDS", "").split(",") if k.strip()]
FIRST_RUN_LOOKBACK_H = int(os.getenv("FIRST_RUN_LOOKBACK_H", "2"))
MAX_AGE_DAYS = int(os.getenv("MAX_AGE_DAYS", "7"))  # ignore les CVE publiées il y a plus longtemps
STARTUP_NOTIFY = os.getenv("STARTUP_NOTIFY", "true").lower() == "true"
STATE_FILE = os.getenv("STATE_FILE", "/data/state.json")

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# NVD : 5 requêtes / 30 s sans clé, 50 / 30 s avec clé
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# gravité -> (priorité ntfy, tags/emoji ntfy, libellé FR)
SEVERITY_STYLE = {
    "CRITICAL": (5, ["rotating_light", "red_circle"], "CRITIQUE"),
    "HIGH":     (4, ["warning", "orange_circle"], "ÉLEVÉE"),
    "MEDIUM":   (3, ["yellow_circle"], "MOYENNE"),
    "LOW":      (2, ["green_circle"], "FAIBLE"),
    None:       (2, ["white_circle"], "NON NOTÉE"),
}

running = True


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def stop(*_):
    global running
    log("Arrêt demandé, fin après le cycle en cours.")
    running = False


# --------------------------------------------------------------------------
# État persistant (dernière vérification + CVE déjà envoyées)
# --------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_check": None, "notified": {}}


def save_state(state):
    # purge des CVE trop anciennes pour garder un fichier léger
    limit = (datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS + 7)).isoformat()
    state["notified"] = {k: v for k, v in state["notified"].items() if v >= limit}
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------
# NVD
# --------------------------------------------------------------------------
def nvd_date(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def nvd_get(params):
    url = NVD_ENDPOINT + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "veilleur-cve/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            wait = 30 * (attempt + 1)
            log(f"NVD HTTP {e.code}, nouvel essai dans {wait}s")
            time.sleep(wait)
        except Exception as e:  # réseau, timeout, JSON...
            wait = 30 * (attempt + 1)
            log(f"NVD erreur ({e}), nouvel essai dans {wait}s")
            time.sleep(wait)
    raise RuntimeError("NVD injoignable après plusieurs essais")


def fetch_modified_cves(start, end):
    """Toutes les CVE créées OU modifiées dans la fenêtre (attrape aussi
    celles qui viennent juste de recevoir leur score CVSS)."""
    out, index = [], 0
    while True:
        data = nvd_get({
            "lastModStartDate": nvd_date(start),
            "lastModEndDate": nvd_date(end),
            "resultsPerPage": PAGE_SIZE,
            "startIndex": index,
        })
        vulns = data.get("vulnerabilities", [])
        out.extend(v["cve"] for v in vulns)
        index += len(vulns)
        if not vulns or index >= data.get("totalResults", 0):
            return out
        time.sleep(NVD_DELAY)


def get_severity(cve):
    """Renvoie (gravité, score, version CVSS) en préférant le score officiel NVD."""
    metrics = cve.get("metrics", {})
    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"),
                       ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        m = entries[0]
        data = m.get("cvssData", {})
        sev = (data.get("baseSeverity") or m.get("baseSeverity") or "").upper()
        if sev in SEVERITY_RANK:
            return sev, data.get("baseScore"), label
    return None, None, None


def get_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def get_products(cve, limit=4):
    prods = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    name = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if name not in prods:
                        prods.append(name)
    return prods[:limit] + (["…"] if len(prods) > limit else [])


def matches_keywords(cve):
    if not KEYWORDS:
        return True
    text = get_description(cve).lower() + " " + json.dumps(cve.get("configurations", [])).lower()
    return any(k in text for k in KEYWORDS)


# --------------------------------------------------------------------------
# ntfy
# --------------------------------------------------------------------------
def ntfy_send(payload):
    payload["topic"] = NTFY_TOPIC
    headers = {"Content-Type": "application/json"}
    if NTFY_TOKEN:
        headers["Authorization"] = f"Bearer {NTFY_TOKEN}"
    elif NTFY_USER:
        import base64
        cred = base64.b64encode(f"{NTFY_USER}:{NTFY_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"
    req = urllib.request.Request(NTFY_URL, data=json.dumps(payload).encode("utf-8"),
                                 headers=headers, method="POST")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20):
                return True
        except Exception as e:
            log(f"ntfy erreur ({e}), essai {attempt + 1}/3")
            time.sleep(5)
    return False


def notify_cve(cve, sev, score, version):
    prio, tags, label = SEVERITY_STYLE[sev]
    cve_id = cve["id"]
    desc = get_description(cve)
    if len(desc) > 400:
        desc = desc[:400].rsplit(" ", 1)[0] + "…"
    lines = []
    if sev:
        lines.append(f"Gravité : {label} — {score} (CVSS {version})")
    else:
        lines.append("Gravité : pas encore notée par le NVD")
    prods = get_products(cve)
    if prods:
        lines.append("Produits : " + ", ".join(prods))
    if cve.get("cisaExploitAdd"):
        lines.append("⚠️ Exploitée activement (catalogue CISA KEV)")
        prio = 5
    lines.append("")
    lines.append(desc)
    return ntfy_send({
        "title": f"{cve_id} · {label}" + (f" {score}" if score is not None else ""),
        "message": "\n".join(lines),
        "priority": prio,
        "tags": tags,
        "click": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    })


# --------------------------------------------------------------------------
# Boucle principale
# --------------------------------------------------------------------------
def run_cycle(state):
    now = datetime.now(timezone.utc)
    if state.get("last_check"):
        start = datetime.fromisoformat(state["last_check"]) - timedelta(minutes=10)  # chevauchement
    else:
        start = now - timedelta(hours=FIRST_RUN_LOOKBACK_H)
    start = max(start, now - timedelta(days=100))  # limite NVD : 120 jours

    cves = fetch_modified_cves(start, now)
    min_publi = (now - timedelta(days=MAX_AGE_DAYS)).isoformat()
    min_rank = SEVERITY_RANK.get(MIN_SEVERITY, 0)
    sent = 0

    # tri du plus grave au moins grave
    def sort_key(c):
        s, score, _ = get_severity(c)
        return -(score or 0)

    for cve in sorted(cves, key=sort_key):
        cve_id = cve["id"]
        if cve_id in state["notified"]:
            continue
        if cve.get("vulnStatus") == "Rejected":
            continue
        published = cve.get("published", "")
        published_iso = published + ("+00:00" if "+" not in published and "Z" not in published else "")
        if published_iso < min_publi:
            continue  # vieille CVE simplement mise à jour
        if not matches_keywords(cve):
            continue
        sev, score, version = get_severity(cve)
        if sev is None and min_rank > 0:
            continue  # pas encore notée : on la reverra quand le NVD lui donnera un score
        if sev is not None and SEVERITY_RANK[sev] < min_rank:
            state["notified"][cve_id] = published_iso  # sous le seuil : on l'ignore définitivement
            continue
        if notify_cve(cve, sev, score, version):
            state["notified"][cve_id] = published_iso
            sent += 1
            time.sleep(0.5)  # évite de saturer ntfy

    state["last_check"] = now.isoformat()
    save_state(state)
    log(f"{len(cves)} CVE créées/modifiées analysées, {sent} notification(s) envoyée(s)")


def main():
    if not NTFY_TOPIC:
        log("ERREUR : la variable NTFY_TOPIC est obligatoire.")
        sys.exit(1)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    log(f"Démarrage — ntfy: {NTFY_URL}/{NTFY_TOPIC}, seuil: {MIN_SEVERITY}, "
        f"intervalle: {CHECK_INTERVAL_MIN} min, mots-clés: {KEYWORDS or 'aucun (tout)'}, "
        f"clé NVD: {'oui' if NVD_API_KEY else 'non'}")
    if STARTUP_NOTIFY:
        ntfy_send({"title": "Veilleur CVE démarré", "priority": 1, "tags": ["shield"],
                   "message": f"Seuil : {MIN_SEVERITY} · vérification toutes les {CHECK_INTERVAL_MIN} min"})

    state = load_state()
    while running:
        try:
            run_cycle(state)
        except Exception as e:
            log(f"Erreur pendant le cycle : {e}")
        for _ in range(CHECK_INTERVAL_MIN * 60):
            if not running:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()

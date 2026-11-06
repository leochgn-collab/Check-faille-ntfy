"""
Cœur du veilleur : configuration, état persistant, sources (NVD + CISA KEV)
et envoi des notifications ntfy.
"""

import base64
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

DATA_DIR = os.getenv("DATA_DIR", "/data")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

UA = "veilleur-cve/2.0"
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_REFRESH_MIN = 60
NVD_PAGE_SIZE = 2000
HISTORY_MAX = 200
MAX_DETAILED_PER_CYCLE = 15   # au-delà : un seul message récapitulatif
SEND_DELAY_S = 1.5            # pause entre deux notifications (évite le 429 de ntfy)

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# gravité -> (priorité ntfy, tags ntfy, libellé)
SEVERITY_STYLE = {
    "CRITICAL": (5, ["rotating_light", "red_circle"], "CRITIQUE"),
    "HIGH": (4, ["warning", "orange_circle"], "ÉLEVÉE"),
    "MEDIUM": (3, ["yellow_circle"], "MOYENNE"),
    "LOW": (2, ["green_circle"], "FAIBLE"),
    None: (2, ["white_circle"], "NON NOTÉE"),
}

DEFAULTS = {
    "ntfy_url": "https://ntfy.sh",
    "ntfy_topic": "",
    "ntfy_user": "",
    "ntfy_password": "",
    "ntfy_token": "",
    "nvd_api_key": "",
    "min_severity": "HIGH",
    "keywords": [],
    "check_interval_min": 15,
    "max_age_days": 7,
    "kev_enabled": True,
    "startup_notify": True,
    "paused": False,
    # heures calmes : aucune notification, tout arrive à la fin de la plage
    "quiet_enabled": True,
    "quiet_start": "19:00",
    "quiet_end": "08:00",
    "timezone": "Europe/Paris",
    # traduction des descriptions (le NVD ne publie qu'en anglais)
    "translate_provider": "none",            # none | libretranslate | deepl
    "libretranslate_url": "http://libretranslate:5000",
    "deepl_api_key": "",
}
SECRET_KEYS = ("ntfy_password", "ntfy_token", "nvd_api_key", "deepl_api_key")
ENV_NAMES = {k: k.upper() for k in DEFAULTS}  # ntfy_url -> NTFY_URL, etc.


def now_utc():
    return datetime.now(timezone.utc)


def log(msg):
    print(f"[{now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC] {msg}", flush=True)


def atomic_write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def _to_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "oui", "on", "o", "y")


def normalize(key, value):
    if key == "keywords":
        if isinstance(value, str):
            value = value.split(",")
        return sorted({str(k).strip().lower() for k in value if str(k).strip()})
    if key in ("check_interval_min", "max_age_days"):
        return int(value)
    if key in ("kev_enabled", "startup_notify", "paused", "quiet_enabled"):
        return _to_bool(value)
    if key == "min_severity":
        return str(value).strip().upper()
    if key == "translate_provider":
        return str(value).strip().lower()
    if key in ("ntfy_url", "libretranslate_url"):
        return str(value).strip().rstrip("/")
    return str(value).strip() if key != "ntfy_password" else str(value)


def validate(cfg):
    errors = []
    if not re.match(r"^https?://[^\s/]+", cfg["ntfy_url"]):
        errors.append("L'URL ntfy doit commencer par http:// ou https://")
    if not re.match(r"^[A-Za-z0-9_-]{1,64}$", cfg["ntfy_topic"]):
        errors.append("Topic ntfy invalide (lettres, chiffres, - et _ uniquement)")
    if cfg["min_severity"] not in SEVERITY_RANK:
        errors.append("Gravité minimale invalide")
    if not 5 <= cfg["check_interval_min"] <= 1440:
        errors.append("L'intervalle doit être entre 5 et 1440 minutes")
    if not 1 <= cfg["max_age_days"] <= 60:
        errors.append("L'âge maximal doit être entre 1 et 60 jours")
    for k in ("quiet_start", "quiet_end"):
        if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", cfg[k]):
            errors.append("Heures calmes : format HH:MM attendu")
            break
    try:
        ZoneInfo(cfg["timezone"])
    except Exception:
        errors.append("Fuseau horaire inconnu")
    if cfg["translate_provider"] not in ("none", "libretranslate", "deepl"):
        errors.append("Service de traduction inconnu")
    if cfg["translate_provider"] == "libretranslate" and not re.match(r"^https?://", cfg["libretranslate_url"]):
        errors.append("L'URL LibreTranslate doit commencer par http:// ou https://")
    if cfg["translate_provider"] == "deepl" and not cfg["deepl_api_key"]:
        errors.append("Il faut une clé API DeepL pour utiliser DeepL")
    if errors:
        raise ValueError(" · ".join(errors))


class Config:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = dict(DEFAULTS)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, encoding="utf-8") as f:
                stored = json.load(f)
            for k, v in stored.items():
                if k in DEFAULTS:
                    try:
                        self.data[k] = normalize(k, v)
                    except (ValueError, TypeError):
                        pass
        else:
            # premier démarrage : on part des variables d'environnement éventuelles
            for k, env in ENV_NAMES.items():
                if os.getenv(env):
                    try:
                        self.data[k] = normalize(k, os.environ[env])
                    except (ValueError, TypeError):
                        pass
            self._save()

    def _save(self):
        atomic_write_json(CONFIG_FILE, self.data)

    def get(self):
        with self.lock:
            return json.loads(json.dumps(self.data))

    def public(self):
        """Config sans les secrets (pour l'interface web)."""
        cfg = self.get()
        for k in SECRET_KEYS:
            cfg["has_" + k] = bool(cfg.pop(k))
        return cfg

    def update(self, changes, clear=()):
        """Secrets : une valeur vide = inchangé ; `clear` = liste des secrets à effacer."""
        with self.lock:
            new = dict(self.data)
            for k, v in changes.items():
                if k not in DEFAULTS:
                    continue
                if k in SECRET_KEYS and (v is None or v == ""):
                    continue
                try:
                    new[k] = normalize(k, v)
                except (ValueError, TypeError):
                    raise ValueError(f"Valeur invalide pour {k}")
            for k in clear:
                if k in SECRET_KEYS:
                    new[k] = ""
            validate(new)
            self.data = new
            self._save()


def quiet_until(cfg, now=None):
    """Si on est dans les heures calmes, renvoie la fin (datetime UTC), sinon None."""
    if not cfg.get("quiet_enabled") or cfg["quiet_start"] == cfg["quiet_end"]:
        return None
    try:
        tz = ZoneInfo(cfg["timezone"])
    except Exception:
        tz = timezone.utc
    local = (now or now_utc()).astimezone(tz)
    sh, sm = map(int, cfg["quiet_start"].split(":"))
    eh, em = map(int, cfg["quiet_end"].split(":"))
    t, start, end = local.hour * 60 + local.minute, sh * 60 + sm, eh * 60 + em
    inside = (start <= t < end) if start < end else (t >= start or t < end)
    if not inside:
        return None
    end_dt = local.replace(hour=eh, minute=em, second=0, microsecond=0)
    if end_dt <= local:
        end_dt += timedelta(days=1)
    return end_dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# État (dernière vérif, CVE déjà envoyées, historique…)
# --------------------------------------------------------------------------
class State:
    FIELDS = {
        "last_check": None, "notified": {}, "history": [], "kev_known": [],
        "kev_last_fetch": None, "since": None, "sent_total": 0, "last_error": None, "last_cycle": None,
    }

    def __init__(self):
        self.lock = threading.RLock()
        self.d = json.loads(json.dumps(self.FIELDS))
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                stored = json.load(f)
            for k in self.FIELDS:
                if k in stored:
                    self.d[k] = stored[k]
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self, max_age_days=7):
        with self.lock:
            limit = (now_utc() - timedelta(days=max_age_days + 14)).isoformat()
            self.d["notified"] = {k: v for k, v in self.d["notified"].items() if v >= limit}
            self.d["history"] = self.d["history"][:HISTORY_MAX]
            atomic_write_json(STATE_FILE, self.d)

    def add_history(self, entry):
        with self.lock:
            self.d["history"].insert(0, entry)
            self.d["sent_total"] += 1

    def snapshot(self):
        with self.lock:
            return {
                "last_check": self.d["last_check"],
                "last_error": self.d["last_error"],
                "last_cycle": self.d["last_cycle"],
                "sent_total": self.d["sent_total"],
                "kev_count": len(self.d["kev_known"]),
                "history": list(self.d["history"][:100]),
            }


# --------------------------------------------------------------------------
# ntfy
# --------------------------------------------------------------------------
NTFY_ERRORS = {
    401: "Utilisateur ou mot de passe ntfy refusé (401)",
    403: "Cet utilisateur n'a pas le droit d'écrire sur ce topic (403)",
    404: "URL ntfy introuvable (404) : vérifie l'adresse du serveur",
    413: "Message trop gros pour le serveur ntfy (413)",
    429: "Le serveur ntfy limite le débit (429), nouvel essai au prochain cycle",
}


def ntfy_send(cfg, payload, timeout=20):
    """Envoie une notification. Renvoie (ok, message, code_http)."""
    body = dict(payload)
    body["topic"] = cfg["ntfy_topic"]
    headers = {"Content-Type": "application/json", "User-Agent": UA}
    if cfg.get("ntfy_token"):
        headers["Authorization"] = "Bearer " + cfg["ntfy_token"]
    elif cfg.get("ntfy_user"):
        cred = f"{cfg['ntfy_user']}:{cfg.get('ntfy_password', '')}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(cred).decode()
    req = urllib.request.Request(cfg["ntfy_url"], data=json.dumps(body).encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True, "Notification envoyée", 200
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode("utf-8", "replace")
        return False, NTFY_ERRORS.get(e.code, f"Erreur ntfy HTTP {e.code} : {detail}"), e.code
    except Exception as e:
        return False, f"Serveur ntfy injoignable : {e}", 0


def ntfy_send_retry(cfg, payload, stop_event):
    for attempt in range(3):
        ok, msg, code = ntfy_send(cfg, payload)
        if ok or 400 <= code < 500:  # erreur de config : inutile d'insister
            return ok, msg, code
        log(f"ntfy : {msg} (essai {attempt + 1}/3)")
        if stop_event.wait(5):
            break
    return False, msg, code


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------
def http_get_json(url, headers=None, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def nvd_date(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def nvd_fetch(cfg, start, end, stop_event):
    """CVE créées OU modifiées dans la fenêtre (attrape celles qui reçoivent leur score)."""
    headers = {"apiKey": cfg["nvd_api_key"]} if cfg["nvd_api_key"] else {}
    delay = 0.7 if cfg["nvd_api_key"] else 6.5  # limites NVD : 50 ou 5 requêtes / 30 s
    out, index = [], 0
    while True:
        params = urllib.parse.urlencode({
            "lastModStartDate": nvd_date(start), "lastModEndDate": nvd_date(end),
            "resultsPerPage": NVD_PAGE_SIZE, "startIndex": index,
        })
        data = None
        for attempt in range(5):
            try:
                data = http_get_json(f"{NVD_ENDPOINT}?{params}", headers)
                break
            except urllib.error.HTTPError as e:
                if e.code == 404 and cfg["nvd_api_key"]:
                    raise RuntimeError("NVD a refusé la requête (clé API NVD invalide ?)")
                err = f"HTTP {e.code}"
            except Exception as e:
                err = str(e)
            wait = 20 * (attempt + 1)
            log(f"NVD : {err}, nouvel essai dans {wait}s")
            if stop_event.wait(wait):
                raise RuntimeError("arrêt demandé")
        if data is None:
            raise RuntimeError(f"NVD injoignable ({err})")
        vulns = data.get("vulnerabilities", [])
        out.extend(v["cve"] for v in vulns)
        index += len(vulns)
        if not vulns or index >= data.get("totalResults", 0):
            return out
        stop_event.wait(delay)


def cve_severity(cve):
    metrics = cve.get("metrics", {})
    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"),
                       ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        sev = (data.get("baseSeverity") or entries[0].get("baseSeverity") or "").upper()
        if sev in SEVERITY_RANK:
            return sev, data.get("baseScore"), label
    return None, None, None


def cve_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def cve_products(cve, limit=4):
    prods = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                p = m.get("criteria", "").split(":")
                if len(p) > 4:
                    name = f"{p[3]} {p[4]}".replace("_", " ")
                    if name not in prods:
                        prods.append(name)
    return prods[:limit] + (["…"] if len(prods) > limit else [])


def keyword_match(cfg, text):
    if not cfg["keywords"]:
        return True
    text = text.lower()
    return any(k in text for k in cfg["keywords"])


def translate_many(cfg, texts):
    """Traduit une liste de textes anglais en français.
    En cas de souci, renvoie les textes d'origine : une alerte ne doit jamais
    être bloquée par la traduction. Renvoie (textes, ok)."""
    provider = cfg.get("translate_provider", "none")
    if provider == "none" or not texts:
        return list(texts), True
    try:
        if provider == "deepl":
            key = cfg["deepl_api_key"]
            host = "api-free.deepl.com" if key.endswith(":fx") else "api.deepl.com"
            req = urllib.request.Request(
                f"https://{host}/v2/translate",
                data=json.dumps({"text": list(texts), "source_lang": "EN", "target_lang": "FR"}).encode(),
                headers={"Authorization": "DeepL-Auth-Key " + key, "Content-Type": "application/json",
                         "User-Agent": UA}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                out = [t["text"] for t in json.load(r)["translations"]]
        else:
            req = urllib.request.Request(
                cfg["libretranslate_url"].rstrip("/") + "/translate",
                data=json.dumps({"q": list(texts), "source": "en", "target": "fr",
                                 "format": "text"}).encode(),
                headers={"Content-Type": "application/json", "User-Agent": UA}, method="POST")
            with urllib.request.urlopen(req, timeout=180) as r:
                out = json.load(r)["translatedText"]
            if isinstance(out, str):
                out = [out]
        if len(out) != len(texts):
            raise ValueError("réponse incomplète")
        return out, True
    except urllib.error.HTTPError as e:
        why = {403: "clé refusée", 456: "quota DeepL du mois épuisé"}.get(e.code, f"HTTP {e.code}")
        log(f"Traduction impossible ({why}) : envoi en anglais")
    except Exception as e:
        log(f"Traduction impossible ({e}) : envoi en anglais")
    return list(texts), False


def shorten(text, n):
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + "…"


# --------------------------------------------------------------------------
# Veilleur (thread de fond)
# --------------------------------------------------------------------------
class Watcher(threading.Thread):
    def __init__(self, config, state):
        super().__init__(daemon=True, name="watcher")
        self.config, self.state = config, state
        self.wake = threading.Event()
        self.stop_event = threading.Event()
        self.busy = False
        self.next_check = None

    def trigger(self):
        self.wake.set()

    def stop(self):
        self.stop_event.set()
        self.wake.set()

    def run(self):
        cfg = self.config.get()
        self.quiet_end = None
        if cfg["startup_notify"] and cfg["ntfy_topic"] and not quiet_until(cfg):
            ok, msg, _ = ntfy_send(cfg, {
                "title": "Veilleur CVE démarré", "priority": 1, "tags": ["shield"],
                "message": f"Seuil : {cfg['min_severity']} · vérification toutes les {cfg['check_interval_min']} min",
            })
            log("Notification de démarrage : " + msg)
        while not self.stop_event.is_set():
            cfg = self.config.get()
            interval = cfg["check_interval_min"] * 60
            quiet = quiet_until(cfg)
            self.quiet_end = quiet.isoformat() if quiet else None
            if cfg["paused"]:
                log("En pause")
            elif not cfg["ntfy_topic"]:
                with self.state.lock:
                    self.state.d["last_error"] = "Topic ntfy non configuré"
            elif quiet:
                # rien n'est envoyé ; la fenêtre NVD n'avance pas, donc tout
                # ce qui sort pendant la nuit sera envoyé à la fin de la plage
                log(f"Heures calmes jusqu'à {quiet.isoformat()}")
                interval = min(interval, max(30, int((quiet - now_utc()).total_seconds()) + 30))
            else:
                self.cycle(cfg)
            self.next_check = (now_utc() + timedelta(seconds=interval)).isoformat()
            self.wake.wait(interval)
            self.wake.clear()

    def cycle(self, cfg):
        self.busy = True
        stats = {"at": now_utc().isoformat(), "nvd_seen": 0, "sent": 0, "kev_sent": 0}
        try:
            self.nvd_cycle(cfg, stats)
            if cfg["kev_enabled"]:
                self.kev_cycle(cfg, stats)
            with self.state.lock:
                self.state.d["last_error"] = stats.get("error")
        except Exception as e:
            log(f"Erreur : {e}")
            with self.state.lock:
                self.state.d["last_error"] = f"{now_utc().strftime('%d/%m %H:%M')} UTC — {e}"
        finally:
            with self.state.lock:
                self.state.d["last_cycle"] = stats
            self.state.save(cfg["max_age_days"])
            self.busy = False
            log(f"Cycle terminé : {stats['nvd_seen']} CVE analysées, "
                f"{stats['sent']} envoyée(s), {stats['kev_sent']} alerte(s) KEV")

    # ---- NVD : nouvelles CVE --------------------------------------------
    def nvd_cycle(self, cfg, stats):
        now = now_utc()
        last = self.state.d["last_check"]
        start = datetime.fromisoformat(last) - timedelta(minutes=10) if last else now - timedelta(hours=2)
        start = max(start, now - timedelta(days=100))  # limite NVD : 120 jours par requête

        # Au tout premier lancement on part de « maintenant » : pas d'avalanche
        # avec toutes les failles des jours précédents.
        with self.state.lock:
            if not self.state.d.get("since"):
                self.state.d["since"] = (now - timedelta(hours=2)).isoformat()
            since = self.state.d["since"]

        cves = nvd_fetch(cfg, start, now, self.stop_event)
        stats["nvd_seen"] = len(cves)
        min_pub = max((now - timedelta(days=cfg["max_age_days"])).isoformat(), since)
        min_rank = SEVERITY_RANK[cfg["min_severity"]]
        notified = self.state.d["notified"]

        # 1) sélection des failles à envoyer
        todo = []
        for cve in cves:
            cid = cve["id"]
            if cid in notified or cve.get("vulnStatus") == "Rejected":
                continue
            pub = cve.get("published", "")
            if "+" not in pub and not pub.endswith("Z"):
                pub += "+00:00"
            if pub < min_pub:
                continue  # trop ancienne, ou publiée avant l'installation
            desc = cve_description(cve)
            if not keyword_match(cfg, desc + " " + json.dumps(cve.get("configurations", []))):
                continue
            sev, score, version = cve_severity(cve)
            if sev is None and min_rank > 0:
                continue  # pas encore notée : on la reverra quand elle aura un score
            if sev is not None and SEVERITY_RANK[sev] < min_rank:
                notified[cid] = pub  # sous le seuil : ignorée définitivement
                continue
            todo.append((cve, sev, score, version, pub, desc))
        todo.sort(key=lambda t: (not t[0].get("cisaExploitAdd"), -(t[2] or 0)))

        # 2) les plus graves une par une, le reste regroupé en un seul message
        detailed, grouped = todo[:MAX_DETAILED_PER_CYCLE], todo[MAX_DETAILED_PER_CYCLE:]
        all_ok = True
        fr_detailed, _ = translate_many(cfg, [shorten(t[5], 700) for t in detailed])
        for (cve, sev, score, version, pub, _), desc in zip(detailed, fr_detailed):
            if self.stop_event.is_set():
                all_ok = False
                break
            cid = cve["id"]
            prio, tags, label = SEVERITY_STYLE[sev]
            lines = [f"Gravité : {label} — {score} (CVSS {version})" if sev
                     else "Gravité : pas encore notée par le NVD"]
            prods = cve_products(cve)
            if prods:
                lines.append("Produits : " + ", ".join(prods))
            if cve.get("cisaExploitAdd"):
                lines.append("⚠️ Exploitée activement (catalogue CISA KEV)")
                prio = 5
            lines += ["", shorten(desc, 400)]
            ok, msg, _ = ntfy_send_retry(cfg, {
                "title": f"{cid} · {label}" + (f" {score}" if score is not None else ""),
                "message": "\n".join(lines), "priority": prio, "tags": tags,
                "click": f"https://nvd.nist.gov/vuln/detail/{cid}",
            }, self.stop_event)
            if not ok:
                stats["error"] = msg
                all_ok = False
                break  # on garde la fenêtre : ce sera renvoyé au prochain cycle
            self._record(cve, sev, score, pub, shorten(desc, 220), prods)
            stats["sent"] += 1
            self.stop_event.wait(SEND_DELAY_S)

        if all_ok and grouped:
            # résumés traduits (les 100 premiers, pour ménager le quota DeepL)
            fr_sum, _ = translate_many(cfg, [shorten(t[5], 220) for t in grouped[:100]])
            summaries = fr_sum + [shorten(t[5], 220) for t in grouped[100:]]
            lines = []
            for (cve, sev, score, version, pub, _), desc in zip(grouped[:40], summaries):
                lines.append(f"{cve['id']} · {SEVERITY_STYLE[sev][2]}" + (f" {score}" if score else "")
                             + " — " + shorten(desc, 70))
            if len(grouped) > 40:
                lines.append(f"… et {len(grouped) - 40} autres (voir l'interface web)")
            top = grouped[0][1]
            ok, msg, _ = ntfy_send_retry(cfg, {
                "title": f"+ {len(grouped)} autres failles",
                "message": "\n".join(lines), "priority": 3,
                "tags": SEVERITY_STYLE[top][1][:1],
            }, self.stop_event)
            if ok:
                for (cve, sev, score, version, pub, _), summary in zip(grouped, summaries):
                    self._record(cve, sev, score, pub, summary, cve_products(cve), grouped=True)
                stats["sent"] += len(grouped)
            else:
                stats["error"] = msg
                all_ok = False

        if all_ok:
            with self.state.lock:
                self.state.d["last_check"] = now.isoformat()

    def _record(self, cve, sev, score, pub, summary, prods, grouped=False):
        self.state.d["notified"][cve["id"]] = pub
        self.state.add_history({
            "id": cve["id"], "source": "NVD", "severity": sev, "score": score,
            "published": pub, "sent_at": now_utc().isoformat(),
            "summary": summary, "products": prods,
            "kev": bool(cve.get("cisaExploitAdd")), "grouped": grouped,
        })

    # ---- CISA KEV : failles exploitées activement ------------------------
    def kev_cycle(self, cfg, stats):
        last = self.state.d["kev_last_fetch"]
        if last and now_utc() - datetime.fromisoformat(last) < timedelta(minutes=KEV_REFRESH_MIN):
            return
        data = http_get_json(KEV_URL)
        vulns = data.get("vulnerabilities", [])
        known = set(self.state.d["kev_known"])
        first_time = not known
        for v in vulns:
            cid = v.get("cveID")
            if not cid or cid in known:
                continue
            if first_time:
                known.add(cid)  # premier passage : on mémorise le catalogue sans notifier
                continue
            text = " ".join(str(v.get(k, "")) for k in
                            ("vendorProject", "product", "vulnerabilityName", "shortDescription"))
            if keyword_match(cfg, text):
                (name, desc), _ = translate_many(cfg, [v.get("vulnerabilityName", ""),
                                                       shorten(v.get("shortDescription", ""), 700)])
                lines = [f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
                         name, "", shorten(desc, 400)]
                if v.get("knownRansomwareCampaignUse") == "Known":
                    lines.append("☠️ Utilisée par des rançongiciels")
                ok, msg, _ = ntfy_send_retry(cfg, {
                    "title": f"{cid} · EXPLOITÉE ACTIVEMENT",
                    "message": "\n".join(lines), "priority": 5, "tags": ["fire", "rotating_light"],
                    "click": f"https://nvd.nist.gov/vuln/detail/{cid}",
                }, self.stop_event)
                if not ok:
                    stats["error"] = msg
                    break
                stats["kev_sent"] += 1
                self.state.add_history({
                    "id": cid, "source": "KEV", "severity": "CRITICAL", "score": None,
                    "published": v.get("dateAdded"), "sent_at": now_utc().isoformat(),
                    "summary": shorten(desc, 220),
                    "products": [f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()],
                    "kev": True,
                })
            known.add(cid)
        with self.state.lock:
            self.state.d["kev_known"] = sorted(known)
            if "error" not in stats:
                self.state.d["kev_last_fetch"] = now_utc().isoformat()

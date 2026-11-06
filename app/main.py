#!/usr/bin/env python3
"""
Veilleur CVE -> ntfy

  python main.py                 lance le service (veilleur + interface web)
  python main.py --init-config   lit des lignes CLE=valeur_base64 sur stdin et les applique
  python main.py --show-config   affiche la config (sans secrets), format cle=valeur
  python main.py --test-ntfy     envoie une notification de test
"""

import base64
import os
import signal
import sys

from core import Config, State, Watcher, ENV_NAMES, SECRET_KEYS, log, ntfy_send


def init_config():
    config = Config()
    changes, clear = {}, []
    names = {v: k for k, v in ENV_NAMES.items()}
    for line in sys.stdin:
        line = line.strip()
        if not line or "=" not in line:
            continue
        name, b64 = line.split("=", 1)
        if name.startswith("CLEAR_") and names.get(name[6:]) in SECRET_KEYS:
            clear.append(names[name[6:]])
        elif name in names:
            changes[names[name]] = base64.b64decode(b64).decode("utf-8")
    try:
        config.update(changes, clear)
    except ValueError as e:
        print(f"Configuration refusée : {e}", file=sys.stderr)
        return 1
    print("Configuration enregistrée.")
    return 0


def show_config():
    for k, v in Config().public().items():
        if isinstance(v, list):
            v = ",".join(v)
        elif isinstance(v, bool):
            v = "true" if v else "false"
        print(f"{k}={v}")
    return 0


def test_ntfy():
    cfg = Config().get()
    if not cfg["ntfy_topic"]:
        print("Topic ntfy non configuré")
        return 1
    ok, msg, _ = ntfy_send(cfg, {"title": "Test du veilleur CVE", "priority": 3,
                                 "message": "Si tu lis ça, tout fonctionne ✅",
                                 "tags": ["white_check_mark"]})
    print(msg)
    return 0 if ok else 1


def serve():
    config, state = Config(), State()
    watcher = Watcher(config, state)

    def stop(*_):
        log("Arrêt…")
        watcher.stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    cfg = config.get()
    log(f"Démarrage — ntfy: {cfg['ntfy_url']}/{cfg['ntfy_topic'] or '(non configuré)'}, "
        f"seuil: {cfg['min_severity']}, intervalle: {cfg['check_interval_min']} min")

    password = os.getenv("WEB_PASSWORD", "")
    if len(password) >= 8:
        from web import WebApp
        WebApp(config, state, watcher, password, int(os.getenv("WEB_INTERNAL_PORT", "8080"))).serve()
    else:
        log("Interface web DÉSACTIVÉE : WEB_PASSWORD absent ou trop court (8 caractères min.)")

    watcher.start()
    while watcher.is_alive():
        watcher.join(1)
    state.save(config.get()["max_age_days"])
    return 0


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.exit({"--init-config": init_config, "--show-config": show_config,
              "--test-ntfy": test_ntfy}.get(arg, serve)())

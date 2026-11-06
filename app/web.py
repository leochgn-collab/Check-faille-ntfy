"""
Interface web : petite API JSON + page unique, protégées par mot de passe.
"""

import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core import log, ntfy_send, quiet_until

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SESSION_TTL = 7 * 24 * 3600
COOKIE = "vcve_session"


class WebApp:
    def __init__(self, config, state, watcher, password, port=8080):
        self.config, self.state, self.watcher = config, state, watcher
        self.password = password
        self.port = port
        self.sessions = {}            # token -> expiration
        self.fail_times = []          # horodatages des échecs de connexion
        self.lock = threading.Lock()

    # ---- sessions --------------------------------------------------------
    def new_session(self):
        token = secrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.sessions = {t: e for t, e in self.sessions.items() if e > now}
            self.sessions[token] = now + SESSION_TTL
        return token

    def valid_session(self, token):
        with self.lock:
            exp = self.sessions.get(token or "")
            return bool(exp and exp > time.time())

    def drop_session(self, token):
        with self.lock:
            self.sessions.pop(token or "", None)

    def check_password(self, pw):
        with self.lock:
            now = time.time()
            self.fail_times = [t for t in self.fail_times if now - t < 600]
            if len(self.fail_times) >= 10:
                return False, "Trop d'essais ratés, réessaie dans quelques minutes"
        ok = hmac.compare_digest(pw.encode("utf-8"), self.password.encode("utf-8"))
        if not ok:
            with self.lock:
                self.fail_times.append(time.time())
            time.sleep(1)
            return False, "Mot de passe incorrect"
        return True, ""

    # ---- statut ----------------------------------------------------------
    def status(self):
        snap = self.state.snapshot()
        cfg = self.config.get()
        snap.update({
            "busy": self.watcher.busy,
            "paused": cfg["paused"],
            "next_check": self.watcher.next_check,
            "quiet_until": getattr(self.watcher, "quiet_end", None),
            "configured": bool(cfg["ntfy_topic"]),
        })
        return snap

    def serve(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "veilleur-cve"
            timeout = 30  # coupe les connexions lentes / bloquées
            sys_version = ""

            def log_message(self, *a):
                pass

            # -- utilitaires --
            def token(self):
                for part in self.headers.get("Cookie", "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == COOKIE:
                        return v
                return None

            def send_json(self, code, obj, extra_headers=()):
                body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                for k, v in extra_headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def read_json(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n < 0 or n > 65536:
                    raise ValueError("Requête trop grosse")
                raw = self.rfile.read(n) if n else b"{}"
                return json.loads(raw or b"{}")

            def authed(self):
                if app.valid_session(self.token()):
                    return True
                self.send_json(401, {"error": "Non connecté"})
                return False

            def cookie(self, value, max_age):
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
                return ("Set-Cookie", f"{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; "
                                      f"Max-Age={max_age}{secure}")

            # -- GET --
            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/health":
                    return self.send_json(200, {"ok": True})
                if path in ("/", "/index.html"):
                    with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("X-Frame-Options", "DENY")
                    self.send_header("Content-Security-Policy",
                                     "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                     "script-src 'self' 'unsafe-inline'; img-src 'self' data:")
                    self.end_headers()
                    return self.wfile.write(body)
                if path == "/api/status":
                    return self.authed() and self.send_json(200, app.status())
                if path == "/api/config":
                    return self.authed() and self.send_json(200, app.config.public())
                self.send_json(404, {"error": "Introuvable"})

            # -- POST --
            def do_POST(self):
                path = self.path.split("?")[0]
                try:
                    body = self.read_json()
                except Exception:
                    return self.send_json(400, {"error": "JSON invalide"})

                if path == "/api/login":
                    ok, err = app.check_password(str(body.get("password", "")))
                    if not ok:
                        return self.send_json(401, {"error": err})
                    return self.send_json(200, {"ok": True},
                                          [self.cookie(app.new_session(), SESSION_TTL)])
                if not self.authed():
                    return
                if path == "/api/logout":
                    app.drop_session(self.token())
                    return self.send_json(200, {"ok": True}, [self.cookie("", 0)])
                if path == "/api/config":
                    try:
                        app.config.update(body.get("config", {}), body.get("clear", []))
                    except ValueError as e:
                        return self.send_json(400, {"error": str(e)})
                    app.watcher.trigger()  # applique tout de suite
                    return self.send_json(200, {"ok": True, "config": app.config.public()})
                if path == "/api/test-ntfy":
                    cfg = app.config.get()
                    if not cfg["ntfy_topic"]:
                        return self.send_json(400, {"error": "Topic ntfy non configuré"})
                    ok, msg, _ = ntfy_send(cfg, {
                        "title": "Test du veilleur CVE", "message": "Si tu lis ça, tout fonctionne ✅",
                        "priority": 3, "tags": ["white_check_mark"],
                    })
                    return self.send_json(200 if ok else 502, {"ok": ok, "message": msg} if ok
                                          else {"error": msg})
                if path == "/api/check-now":
                    if app.watcher.busy:
                        return self.send_json(409, {"error": "Une vérification est déjà en cours"})
                    quiet = quiet_until(app.config.get())
                    if quiet:
                        return self.send_json(409, {"error": "Heures calmes : rien n'est vérifié ni envoyé "
                                                             "avant la fin de la plage"})
                    app.watcher.trigger()
                    return self.send_json(200, {"ok": True})
                self.send_json(404, {"error": "Introuvable"})

        server = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True, name="web").start()
        log(f"Interface web en écoute sur le port {self.port}")
        return server

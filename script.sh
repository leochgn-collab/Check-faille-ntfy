#!/usr/bin/env bash
# =============================================================================
#  Veilleur CVE -> ntfy : installation et configuration
#
#  ./script.sh            configure (ou reconfigure) et lance tout
#  ./script.sh update     récupère la dernière version (git pull) et relance
#  ./script.sh test       envoie une notification de test
#  ./script.sh logs       affiche les logs en direct
#  ./script.sh status     état du conteneur
#  ./script.sh restart    redémarre
#  ./script.sh stop       arrête
#  ./script.sh password   change le mot de passe de l'interface web
# =============================================================================
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

SERVICE=veilleur-cve
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
info()  { echo "${C}›${N} $*"; }
ok()    { echo "${G}✔${N} $*"; }
warn()  { echo "${Y}!${N} $*"; }
die()   { echo "${R}✘ $*${N}" >&2; exit 1; }
title() { echo; echo "${B}━━ $* ━━${N}"; }

# ---------------------------------------------------------------- docker ----
detect_docker() {
  command -v docker >/dev/null 2>&1 \
    || die "Docker n'est pas installé. Installe-le avec : curl -fsSL https://get.docker.com | sh"
  SUDO=""
  if ! docker info >/dev/null 2>&1; then
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
      $SUDO docker info >/dev/null 2>&1 || die "Docker ne répond pas (le service est-il démarré ?)"
    else
      die "Docker ne répond pas (démarre-le : systemctl start docker)"
    fi
  fi
  if $SUDO docker compose version >/dev/null 2>&1; then
    DC=($SUDO docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    DC=($SUDO docker-compose)
  else
    die "Docker Compose introuvable. Sur Debian : apt install docker-compose-plugin"
  fi
}

run_app() { "${DC[@]}" run --rm --no-deps -T "$SERVICE" python main.py "$@"; }

# ------------------------------------------------------------- questions ----
ask() {          # ask VAR "Question" "défaut"
  local _v
  read -r -p "  $2${3:+ ${D}[$3]${N}} : " _v || true
  printf -v "$1" '%s' "${_v:-${3:-}}"
}
ask_secret() {   # ask_secret VAR "Question"
  local _v
  read -r -s -p "  $2 : " _v || true
  echo
  printf -v "$1" '%s' "$_v"
}
yesno() {        # yesno "Question" o|n   -> code retour 0 si oui
  local _d=$2 _r _h="o/N"
  [ "$_d" = o ] && _h="O/n"
  read -r -p "  $1 ${D}[$_h]${N} : " _r || true
  [[ "${_r:-$_d}" =~ ^[oOyY] ]]
}
choose() {       # choose VAR "Question" défaut "choix 1" "choix 2" ...
  local _var=$1 _q=$2 _def=$3 _i=1 _r
  shift 3
  echo "  $_q"
  for _o in "$@"; do echo "    ${B}$_i${N}) $_o"; _i=$((_i + 1)); done
  while true; do
    read -r -p "  Choix ${D}[$_def]${N} : " _r || true
    _r=${_r:-$_def}
    if [[ "$_r" =~ ^[0-9]+$ ]] && [ "$_r" -ge 1 ] && [ "$_r" -le $# ]; then break; fi
    warn "Tape un numéro entre 1 et $#"
  done
  printf -v "$_var" '%s' "$_r"
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
INIT=""
set_cfg()   { INIT+="$1=$(b64 "$2")"$'\n'; }
clear_cfg() { INIT+="CLEAR_$1=x"$'\n'; }

gen_password() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 20 || true; }

# ------------------------------------------------------------------ .env ----
env_get() { [ -f .env ] && grep -E "^$1=" .env | tail -1 | cut -d= -f2- | sed "s/^'//; s/'\$//" || true; }

write_env() {
  ( umask 077
    cat > .env <<EOF
# Généré par ./script.sh le $(date '+%d/%m/%Y %H:%M')
WEB_PASSWORD='$WEB_PASSWORD'
WEB_PORT=$WEB_PORT
WEB_BIND=$WEB_BIND
EOF
  )
}

valid_web_password() {
  [ ${#1} -ge 8 ] || { warn "8 caractères minimum"; return 1; }
  [[ "$1" != *"'"* ]] || { warn "Le caractère ' n'est pas autorisé"; return 1; }
  return 0
}

ask_web_password() {
  while true; do
    ask_secret WEB_PASSWORD "Mot de passe de l'interface web (Entrée = en générer un)"
    if [ -z "$WEB_PASSWORD" ]; then
      WEB_PASSWORD=$(gen_password)
      GENERATED_PW=1
      break
    fi
    valid_web_password "$WEB_PASSWORD" && break
  done
}

server_ip() { hostname -I 2>/dev/null | awk '{print $1}' || true; }

# ------------------------------------------------------------- configure ----
declare -A CUR=()
load_current() {
  local line
  while IFS= read -r line; do
    if [[ $line == *=* ]]; then CUR[${line%%=*}]=${line#*=}; fi
  done < <(run_app --show-config 2>/dev/null || true)
}

configure_ntfy() {
  title "Serveur ntfy"
  local url topic mode user pw token def_url def_topic
  # tant que rien n'est configuré, on propose le serveur ntfy du réseau local
  if [ -n "${CUR[ntfy_topic]:-}" ]; then
    def_url=${CUR[ntfy_url]}; def_topic=${CUR[ntfy_topic]}
  else
    def_url="http://192.168.1.208:2586"; def_topic="failles-securite"
  fi
  while true; do
    ask url "URL de ton serveur ntfy" "$def_url"
    [[ "$url" =~ ^https?:// ]] && break
    warn "L'URL doit commencer par http:// ou https://"
  done
  while true; do
    ask topic "Topic où envoyer les alertes" "$def_topic"
    [[ "$topic" =~ ^[A-Za-z0-9_-]{1,64}$ ]] && break
    warn "Lettres, chiffres, - et _ uniquement"
  done
  set_cfg NTFY_URL "$url"
  set_cfg NTFY_TOPIC "$topic"

  # 1 = token (conseillé), 2 = utilisateur + mot de passe, 3 = rien
  local def_mode=1
  if [ "${CUR[has_ntfy_token]:-false}" != true ] && [ -n "${CUR[ntfy_user]:-}" ]; then def_mode=2; fi
  echo
  echo "  ${D}Le plus sûr : un compte ntfy qui peut SEULEMENT écrire sur ce topic, avec un token."
  echo "  Si ce n'est pas déjà fait, lance ces 3 commandes sur le serveur ntfy :"
  echo "      ntfy user add cve-bot"
  echo "      ntfy access cve-bot $topic write-only"
  echo "      ntfy token add cve-bot          ← copie le token tk_… affiché${N}"
  echo
  choose mode "Comment le veilleur se connecte à ntfy ?" "$def_mode" \
    "Token d'accès tk_… (conseillé)" "Utilisateur + mot de passe" "Pas d'authentification"

  case $mode in
    1)
      while true; do
        if [ "${CUR[has_ntfy_token]:-false}" = true ]; then
          ask_secret token "Token ntfy (Entrée = garder l'actuel)"
          break
        fi
        ask_secret token "Token ntfy (tk_…)"
        [ -n "$token" ] && break
        warn "Le token est obligatoire"
      done
      if [ -n "$token" ]; then set_cfg NTFY_TOKEN "$token"; fi
      set_cfg NTFY_USER ""
      clear_cfg NTFY_PASSWORD
      ;;
    2)
      while true; do
        ask user "Utilisateur ntfy" "${CUR[ntfy_user]:-}"
        [ -n "$user" ] && break
        warn "L'utilisateur est obligatoire"
      done
      set_cfg NTFY_USER "$user"
      while true; do
        if [ "${CUR[has_ntfy_password]:-false}" = true ]; then
          ask_secret pw "Mot de passe ntfy (Entrée = garder l'actuel)"
          break
        fi
        ask_secret pw "Mot de passe ntfy"
        [ -n "$pw" ] && break
        warn "Le mot de passe est obligatoire"
      done
      if [ -n "$pw" ]; then set_cfg NTFY_PASSWORD "$pw"; fi
      clear_cfg NTFY_TOKEN
      ;;
    3)
      set_cfg NTFY_USER ""
      clear_cfg NTFY_PASSWORD
      clear_cfg NTFY_TOKEN
      ;;
  esac
}

configure_filters() {
  title "Quelles failles veux-tu recevoir ?"
  local levels=(NONE LOW MEDIUM HIGH CRITICAL) def=4 i sev kw kev
  for i in "${!levels[@]}"; do
    [ "${levels[$i]}" = "${CUR[min_severity]:-HIGH}" ] && def=$((i + 1))
  done
  choose sev "Gravité minimale" "$def" \
    "Toutes (~100 à 150 notifications / jour !)" \
    "Faible et plus" \
    "Moyenne et plus" \
    "Élevée et critique (~20 à 40 / jour, conseillé)" \
    "Critique uniquement"
  set_cfg MIN_SEVERITY "${levels[$((sev - 1))]}"

  echo
  echo "  ${D}Mots-clés : ne garder que les failles qui parlent de certains logiciels"
  echo "  (ex : debian,apache,php,openssh,docker). Vide = toutes. « - » = effacer.${N}"
  ask kw "Mots-clés" "${CUR[keywords]:-}"
  [ "$kw" = "-" ] && kw=""
  set_cfg KEYWORDS "$kw"

  echo
  local kdef=o
  [ "${CUR[kev_enabled]:-true}" = false ] && kdef=n
  if yesno "Alerter aussi quand une faille devient « exploitée activement » (CISA KEV) ?" "$kdef"; then
    set_cfg KEV_ENABLED true
  else
    set_cfg KEV_ENABLED false
  fi
}

configure_misc() {
  title "Fonctionnement"
  local interval key
  while true; do
    ask interval "Vérifier toutes les combien de minutes ?" "${CUR[check_interval_min]:-15}"
    [[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 5 ] && [ "$interval" -le 1440 ] && break
    warn "Entre 5 et 1440"
  done
  set_cfg CHECK_INTERVAL_MIN "$interval"

  echo
  echo "  ${D}Clé API NVD gratuite (facultative, rend les requêtes 10x plus rapides) :"
  echo "  https://nvd.nist.gov/developers/request-an-api-key${N}"
  if [ "${CUR[has_nvd_api_key]:-false}" = true ]; then
    ask_secret key "Clé API NVD (Entrée = garder, « - » = supprimer)"
  else
    ask_secret key "Clé API NVD (Entrée = aucune)"
  fi
  if [ "$key" = "-" ]; then clear_cfg NVD_API_KEY
  elif [ -n "$key" ]; then set_cfg NVD_API_KEY "$key"
  fi
}

configure_web() {
  title "Interface web"
  while true; do
    ask WEB_PORT "Port de l'interface web" "$(env_get WEB_PORT | grep . || echo 8080)"
    [[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] && break
    warn "Port invalide"
  done
  local bdef=1 b
  [ "$(env_get WEB_BIND)" = "0.0.0.0" ] && bdef=2
  echo
  choose b "Qui peut ouvrir l'interface ?" "$bdef" \
    "Seulement ce serveur (127.0.0.1) — à utiliser avec un reverse proxy Apache/Nginx en HTTPS" \
    "Tout le réseau (http://IP:port) — protégé par mot de passe, mais sans HTTPS"
  [ "$b" = 1 ] && WEB_BIND=127.0.0.1 || WEB_BIND=0.0.0.0

  echo
  local old
  old=$(env_get WEB_PASSWORD)
  GENERATED_PW=0
  if [ "${FRESH:-0}" = 0 ] && [ -n "$old" ] && [ "$old" != "change-moi-svp" ] && yesno "Garder le mot de passe actuel de l'interface web ?" o; then
    WEB_PASSWORD=$old
  else
    ask_web_password
  fi
}

do_configure() {
  detect_docker
  echo "${B}🛡️  Veilleur CVE → ntfy — configuration${N}"
  echo "${D}Appuie sur Entrée pour garder la valeur entre crochets.${N}"

  # .env provisoire pour que docker compose puisse tourner
  FRESH=0
  if [ ! -f .env ]; then
    FRESH=1
    WEB_PASSWORD=$(gen_password); WEB_PORT=8080; WEB_BIND=127.0.0.1
    write_env
  fi

  title "Préparation"
  info "Construction de l'image Docker…"
  "${DC[@]}" build --quiet >/dev/null 2>&1 || "${DC[@]}" build
  ok "Image prête"
  load_current
  [ -n "${CUR[ntfy_topic]:-}" ] && info "Configuration existante trouvée, ses valeurs sont proposées par défaut."

  while true; do
    INIT=""
    configure_ntfy
    printf '%s' "$INIT" | run_app --init-config >/dev/null || die "Configuration ntfy refusée"
    load_current
    info "Envoi d'une notification de test…"
    if run_app --test-ntfy; then
      ok "Notification reçue par ntfy — regarde ton téléphone !"
      break
    fi
    warn "Le test a échoué."
    yesno "Recommencer la configuration ntfy ?" o || break
  done

  INIT=""
  configure_filters
  configure_misc
  printf '%s' "$INIT" | run_app --init-config >/dev/null || die "Configuration refusée"
  configure_web
  write_env
  ok "Configuration enregistrée"

  title "Lancement"
  "${DC[@]}" up -d --force-recreate
  sleep 3
  if "${DC[@]}" ps --status running 2>/dev/null | grep -q "$SERVICE" || $SUDO docker ps --format '{{.Names}}' | grep -qx "$SERVICE"; then
    ok "Le veilleur tourne !"
  else
    warn "Le conteneur ne semble pas démarré, regarde : ./script.sh logs"
  fi

  title "C'est prêt"
  if [ "$WEB_BIND" = "0.0.0.0" ]; then
    echo "  Interface web : ${B}http://$(server_ip):$WEB_PORT${N}"
  else
    echo "  Interface web : ${B}http://127.0.0.1:$WEB_PORT${N} (uniquement depuis le serveur)"
    echo "  ${D}Pour y accéder depuis ton PC sans reverse proxy :"
    echo "    ssh -L $WEB_PORT:127.0.0.1:$WEB_PORT utilisateur@$(server_ip)"
    echo "  puis ouvre http://localhost:$WEB_PORT — exemple Apache dans le README.${N}"
  fi
  if [ "${GENERATED_PW:-0}" = 1 ]; then
    echo "  Mot de passe  : ${B}$WEB_PASSWORD${N}  ${Y}← note-le !${N}"
  fi
  echo
  echo "  ${D}Commandes utiles : ./script.sh logs | test | status | update | password${N}"
}

# ------------------------------------------------------------ commandes ----
case "${1:-config}" in
  config|install|setup)
    do_configure ;;
  update)
    detect_docker
    if [ -d .git ]; then info "Récupération de la dernière version…"; git pull --ff-only; fi
    "${DC[@]}" up -d --build
    ok "À jour" ;;
  test)
    detect_docker; run_app --test-ntfy ;;
  logs)
    detect_docker; "${DC[@]}" logs -f --tail 100 ;;
  status)
    detect_docker; "${DC[@]}" ps ;;
  restart)
    detect_docker; "${DC[@]}" restart; ok "Redémarré" ;;
  stop)
    detect_docker; "${DC[@]}" down; ok "Arrêté (la configuration est conservée)" ;;
  password)
    detect_docker
    [ -f .env ] || die "Lance d'abord ./script.sh"
    WEB_PORT=$(env_get WEB_PORT); WEB_BIND=$(env_get WEB_BIND); GENERATED_PW=0
    ask_web_password
    write_env
    "${DC[@]}" up -d --force-recreate
    ok "Mot de passe changé"
    if [ "$GENERATED_PW" = 1 ]; then echo "  Nouveau mot de passe : ${B}$WEB_PASSWORD${N}"; fi ;;
  -h|--help|help)
    sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//' ;;
  *)
    die "Commande inconnue : $1 (essaie ./script.sh help)" ;;
esac

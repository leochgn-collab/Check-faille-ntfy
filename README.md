# 🛡️ Veilleur CVE → ntfy

Par défaut, il ne surveille **que les failles Proxmox** (modifiable : « Logiciels surveillés »
dans `./script.sh` ou l'interface web).

Surveille 24h/24 les nouvelles failles de sécurité et t'envoie une notification ntfy
pour chacune, avec une priorité qui dépend de sa gravité. Le tout se règle depuis
une interface web.

**Sources**
- **NVD (NIST)** : toutes les nouvelles CVE, avec leur score CVSS.
- **CISA KEV** : alerte dès qu'une faille est ajoutée au catalogue des failles
  *exploitées activement* par des attaquants, même si c'est une vieille CVE.

| Gravité | Priorité ntfy |
|---|---|
| Exploitée activement (KEV) | 5 · urgente 🔥 |
| CRITIQUE (9.0–10) | 5 · urgente |
| ÉLEVÉE (7.0–8.9) | 4 · haute |
| MOYENNE (4.0–6.9) | 3 · normale |
| FAIBLE / pas encore notée | 2 · basse |

## Installation

Il faut Docker et Docker Compose sur le serveur.

```bash
git clone https://github.com/leochgn-collab/Check-faille-ntfy.git
cd Check-faille-ntfy
chmod +x script.sh
./script.sh
```

**Avant**, sur le serveur ntfy, crée un compte qui peut seulement écrire sur le topic
(le plus sûr : même si le conteneur est piraté, il ne peut rien lire ni toucher d'autre) :

```bash
ntfy user add cve-bot
ntfy access cve-bot failles-securite write-only
ntfy token add cve-bot      # copie le token tk_… pour le script
```

Le script pose les questions (serveur ntfy, utilisateur et mot de passe, gravité
minimale, mots-clés…), envoie une **notification de test**, lance le conteneur et
t'affiche l'adresse de l'interface web.

## Commandes

| Commande | Effet |
|---|---|
| `./script.sh` | (re)configurer et relancer |
| `./script.sh test` | envoyer une notification de test |
| `./script.sh logs` | voir les logs en direct |
| `./script.sh status` | état du conteneur |
| `./script.sh update` | récupérer la dernière version et relancer |
| `./script.sh password` | changer le mot de passe de l'interface web |
| `./script.sh restart` / `stop` | redémarrer / arrêter |

## Interface web

- tableau de bord : dernière vérification, alertes envoyées, erreurs éventuelles
- boutons **Vérifier maintenant**, **Notification de test**, **Pause**
- historique des 100 dernières alertes, filtrable par gravité
- tous les réglages, appliqués immédiatement (sans redémarrage)

Par défaut elle n'écoute que sur `127.0.0.1` (le serveur lui-même). Pour y accéder
proprement en HTTPS, ajoute un reverse proxy Apache, par exemple sur un sous-domaine :

```apache
<VirtualHost *:443>
    ServerName cve.mondomaine.fr
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    RequestHeader set X-Forwarded-Proto "https"
    # + tes lignes SSLCertificateFile / SSLCertificateKeyFile (Let's Encrypt)
</VirtualHost>
```

(`a2enmod proxy proxy_http headers` puis `systemctl reload apache2`.)
Ça marche aussi dans un sous-dossier : `ProxyPass /cve/ http://127.0.0.1:8080/`.

## Alertes en français

Le NVD publie les descriptions en anglais. `./script.sh` propose de les traduire :

- **Traducteur local (LibreTranslate)** : un 2ᵉ conteneur à côté du veilleur. Gratuit, sans
  compte, rien ne sort du réseau. Environ 2 Go de disque ; au premier démarrage il
  télécharge ses modèles (quelques minutes).
- **DeepL** : meilleure qualité, avec une clé API gratuite (500 000 caractères/mois).

Si la traduction échoue, l'alerte part quand même, en anglais.

## Heures calmes

Par défaut, aucune notification de 19 h à 8 h (heure de Paris) : ce qui sort pendant la
nuit arrive le matin. Réglable dans l'interface.

## Bon à savoir

- **Volume** : avec le filtre Proxmox, quelques failles par mois. Sans filtre, c'est
  ~100 à 150 nouvelles CVE par jour.
- **Failles pas encore notées** : le NVD met parfois quelques jours à donner un
  score. Avec un seuil, la faille est envoyée dès qu'elle reçoit son score.
- **Pas de doublons, rien de perdu** : si ntfy est injoignable, les alertes sont
  renvoyées au cycle suivant. L'état et la config sont dans un volume Docker,
  donc gardés après un redémarrage ou une mise à jour.
- **Clé API NVD** (gratuite, conseillée) : https://nvd.nist.gov/developers/request-an-api-key
- **Sécurité** : le mot de passe ntfy est stocké dans le volume Docker (fichier
  lisible uniquement par le conteneur) et n'est jamais renvoyé à l'interface web.

# Veilleur CVE → ntfy

Surveille 24h/24 les nouvelles failles de sécurité (CVE) publiées par le NVD (NIST)
et envoie chacune sur un topic ntfy avec une priorité selon sa gravité :

| Gravité CVSS | Priorité ntfy |
|---|---|
| CRITIQUE (9.0–10) ou exploitée activement (CISA KEV) | 5 – urgente |
| ÉLEVÉE (7.0–8.9) | 4 – haute |
| MOYENNE (4.0–6.9) | 3 – normale |
| FAIBLE / pas encore notée | 2 – basse |

Un clic sur la notification ouvre la fiche de la CVE sur nvd.nist.gov.

## Installation

```bash
cp .env.example .env
nano .env          # NTFY_URL, NTFY_TOPIC, éventuellement NVD_API_KEY / MIN_SEVERITY / KEYWORDS
docker compose up -d --build
docker compose logs -f
```

## Bon à savoir

- **Volume** : ~100 à 150 nouvelles CVE par jour. Avec `MIN_SEVERITY=NONE` tu reçois tout.
  `MIN_SEVERITY=HIGH` ramène ça à ~20–40/jour, `KEYWORDS=debian,apache,php` à presque rien
  sauf ce qui te concerne.
- **Failles pas encore notées** : le NVD met parfois plusieurs jours à donner un score.
  Si tu as un seuil (`MIN_SEVERITY` ≠ `NONE`), la faille est envoyée dès qu'elle reçoit
  son score, si elle dépasse le seuil (jusqu'à 7 jours après publication).
- **Pas de doublons** : l'état est stocké dans le volume `/data`, donc un redémarrage
  ne renvoie rien deux fois.
- **Clé API NVD** (gratuite) : conseillée, sinon l'API limite à 5 requêtes / 30 s.

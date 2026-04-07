# veille-secu

Moteur de veille cybersecurite minimaliste. Collecte, filtre et notifie les CVEs et advisories pertinents pour un stack technique declare.

## Fonctionnalites

- 5 sources fiables : NVD, CERT-FR, GitHub Advisories, CISA KEV, Exploit-DB
- Filtrage par stack via WATCH_STACK
- Stockage SQLite
- Notifications Ntfy pour les alertes critiques
- API HTTP simple (FastAPI)
- Dashboard optionnel pour tester les requetes

## Demarrage rapide

```bash
cp .env.example .env
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m src.main
```

Ou via Docker :

```bash
docker compose up --build
```

## API

- GET /api/alerts?severity=&tool=&status=&limit=&offset=
- GET /api/alerts/:id
- PATCH /api/alerts/:id
- GET /api/tools
- POST /api/tools
- DELETE /api/tools/:id
- GET /api/stats
- GET /health
- POST /api/collect (declenche une collecte manuelle, avec cooldown)

## Dashboard (optionnel)

Activer via `DASHBOARD_ENABLED=true`, puis ouvrir `/dashboard`.

## Verifier que la veille tourne

- GET /api/stats pour voir `total` augmenter
- GET /api/alerts?limit=5 pour voir les alertes stockees
- GET /api/tools pour verifier le matching avec WATCH_STACK
- POST /api/collect si tu veux forcer une collecte

## Variables d'environnement

Voir .env.example pour la liste complete des variables.

## Notes

- Les alertes sont dedupliquees par CVE ID ou lien.
- Seules les alertes matchant WATCH_STACK sont conservees.
- Les notifications Ntfy sont envoyees pour les alertes critical.

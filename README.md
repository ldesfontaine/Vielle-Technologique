# veille-securite

Moteur de veille en cybersécurité qui collecte, normalise et filtre les
vulnérabilités et avis de sécurité pertinents pour un ensemble de technologies
déclaré.

## Fonctionnalités

- collecte depuis NVD, CERT-FR, GitHub Advisories, CISA KEV et Exploit-DB ;
- filtrage selon les technologies suivies dans `WATCH_STACK` ;
- stockage local dans SQLite ;
- notifications Ntfy pour les alertes critiques ;
- API HTTP avec FastAPI ;
- tableau de bord optionnel pour consulter et tester les résultats.

## Démarrage rapide

```bash
cp .env.example .env
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m src.main
```

Avec Docker :

```bash
docker compose up --build
```

## API

- `GET /api/alerts?severity=&tool=&status=&limit=&offset=`
- `GET /api/alerts/:id`
- `PATCH /api/alerts/:id`
- `GET /api/tools`
- `POST /api/tools`
- `DELETE /api/tools/:id`
- `GET /api/stats`
- `GET /health`
- `POST /api/collect`

La collecte manuelle possède un délai de protection afin d'éviter les
déclenchements répétés.

## Vérifier la collecte

- `GET /api/stats` permet de vérifier que le nombre d'alertes évolue ;
- `GET /api/alerts?limit=5` affiche les dernières alertes stockées ;
- `GET /api/tools` expose les technologies actuellement suivies ;
- `POST /api/collect` force une collecte manuelle.

## Configuration

Les variables disponibles sont documentées dans `.env.example`.

Les alertes sont dédupliquées par identifiant CVE ou par lien. Seules celles
qui correspondent à `WATCH_STACK` sont conservées. Les notifications Ntfy sont
réservées aux alertes critiques.

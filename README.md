# 🛡️ Vielle-Cyber — Moteur de Veille Cybersécurité

Un moteur de veille cybersécurité en temps réel qui collecte, normalise, enrichit et score des événements de menaces depuis plus de 30 sources hétérogènes (RSS, abuse.ch, ransomware.live).

---

## Architecture

```
src/
├── config/
│   ├── feeds.ts                # 30+ feeds RSS avec tiers de crédibilité
│   └── threat-sources.ts       # APIs threat intel (abuse.ch, ransomware.live)
├── models/
│   └── unified-event.ts        # Modèle UnifiedThreatEvent commun
├── normalizers/
│   ├── rss-normalizer.ts       # RSS/Atom XML → UnifiedThreatEvent
│   ├── abusech-normalizer.ts   # abuse.ch JSON → UnifiedThreatEvent
│   └── ransomware-normalizer.ts # ransomware.live → UnifiedThreatEvent
├── extractors/
│   ├── cve-extractor.ts        # Extraction CVE-YYYY-NNNNN
│   ├── ioc-extractor.ts        # IPs publiques, domaines, hashes
│   └── keyword-classifier.ts   # Mots-clés cybersécurité → scoring
├── enrichment/
│   └── cross-correlator.ts     # Corrélation CVE ↔ articles, IOC ↔ news
├── scoring/
│   └── threat-scorer.ts        # Scoring multi-facteurs (0-100)
├── cache/
│   └── redis.ts                # Redis + fallback mémoire, anti thundering herd
├── fetchers/
│   ├── rss-fetcher.ts          # HTTP RSS avec circuit breaker
│   └── threat-fetcher.ts       # APIs threat intel
├── poll-loop.ts                # Smart poll avec jitter, backoff, stagger
├── data-lifecycle.ts           # TTL adaptatifs par type d'événement
└── index.ts                    # API HTTP + point d'entrée
```

---

## Démarrage

### Prérequis

- Node.js 20+ (ou Bun)
- Redis Upstash (optionnel — fallback mémoire intégré)

### Installation

```bash
npm install
```

### Configuration

Copier le fichier d'exemple et configurer les variables :

```bash
cp .env.example .env
```

Variables disponibles :

| Variable | Description | Requis |
|----------|-------------|--------|
| `UPSTASH_REDIS_REST_URL` | URL REST de votre instance Upstash Redis | Non* |
| `UPSTASH_REDIS_REST_TOKEN` | Token d'authentification Upstash | Non* |
| `PORT` | Port du serveur HTTP (défaut: 3000) | Non |
| `URGENT_SCORE_THRESHOLD` | Seuil de score pour isUrgent (défaut: 70) | Non |
| `OTX_API_KEY` | Clé API AlienVault OTX | Non |
| `ABUSEIPDB_API_KEY` | Clé API AbuseIPDB | Non |

*Sans Redis, les données sont stockées en mémoire et perdues au redémarrage.

### Lancement

```bash
# Mode développement
npm run dev

# Production (compiler puis démarrer)
npm run build && npm start
```

---

## Sources de données

### Tier 1 — Sources officielles

| Source | Type | Intervalle |
|--------|------|-----------|
| CERT-FR | Advisories | 15 min |
| CISA Advisories | Advisories | 15 min |
| CISA KEV | Vulnérabilités | 30 min |
| NVD CVE | Vulnérabilités | 30 min |
| ANSSI | Publications | 1h |
| Microsoft MSRC | Patches | 1h |
| CERT-EU | Advisories | 1h |
| NCSC UK | Advisories | 1h |

### Tier 2 — Médias spécialisés

| Source | Type | Intervalle |
|--------|------|-----------|
| BleepingComputer | Actualités | 10 min |
| The Hacker News | Actualités | 10 min |
| Krebs on Security | Actualités | 30 min |
| Dark Reading | Actualités | 15 min |
| SecurityWeek | Actualités | 15 min |
| Threatpost | Actualités | 15 min |

### Tier 3 — Blogs experts & recherche

| Source | Type | Intervalle |
|--------|------|-----------|
| Cisco Talos | Threat Intel | 1h |
| CrowdStrike | Threat Intel | 1h |
| Mandiant | Threat Intel | 2h |
| SANS ISC | Threat Intel | 30 min |
| Google Project Zero | Vulnérabilités | 24h |
| Exploit-DB | Exploits | 30 min |
| Sekoia Blog | Threat Intel | 2h |

### Sources API — Threat Intelligence

| Source | Type | Intervalle |
|--------|------|-----------|
| Feodo Tracker (abuse.ch) | IOC — C2 IPs | 1h |
| URLhaus (abuse.ch) | IOC — URLs malveillantes | 30 min |
| ThreatFox (abuse.ch) | IOC — Multi-types | 1h |
| MalwareBazaar (abuse.ch) | IOC — Hashes malware | 1h |
| Ransomware.live | Victimes ransomware | 30 min |

---

## Algorithme de Scoring

Le score final est calculé sur une échelle de **0 à 100** :

```
Score = Base(tier) + Type + Contenu(keywords) + Entités - Bruit
```

### Score de base par tier

| Tier | Sources | Score de base |
|------|---------|--------------|
| 1 | CISA, CERT-FR, ANSSI | +50 |
| 2 | BleepingComputer, Krebs | +35 |
| 3 | Schneier, Talos, CrowdStrike | +20 |
| 4 | Reddit, blogs communautaires | +10 |

### Modificateurs de contenu

| Condition | Bonus |
|-----------|-------|
| zero-day / actively exploited | +30 |
| Ransomware (avec nom de groupe) | +25 |
| RANSOMWARE (type) | +15 |
| critical / CVSSv3 9+ | +20 |
| proof of concept / PoC | +20 |
| data breach | +20 |
| supply chain | +25 |
| apt / nation-state | +20 |
| patch released | +15 |
| CVE présente | +10 |
| IOCs (IPs, hashes) | +10 |
| Plusieurs malwares identifiés | +5 par malware (max 3) |

### Démotions (filtre anti-bruit)

| Condition | Malus |
|-----------|-------|
| opinion / editorial / review | -15 |
| rumor / unconfirmed | -10 |
| weekly roundup / newsletter | -10 |

### Seuils de sévérité

| Score | Sévérité | isUrgent |
|-------|---------|---------|
| ≥ 70 | 🔴 critical | ✅ |
| ≥ 55 | 🟠 high | ❌ |
| ≥ 40 | 🟡 medium | ❌ |
| ≥ 25 | 🔵 low | ❌ |
| < 25 | ⚪ info | ❌ |

---

## API HTTP

### `GET /api/feed`

Retourne les événements récents triés par score décroissant.

**Paramètres de requête :**

| Paramètre | Valeurs | Description |
|-----------|---------|-------------|
| `type` | `NEWS`, `VULNERABILITY`, `IOC`, `ADVISORY`, `RANSOMWARE` | Filtrer par type |
| `severity` | `critical`, `high`, `medium`, `low`, `info` | Filtrer par sévérité |
| `source` | Texte libre | Filtrer par nom de source |
| `limit` | Nombre (max 200, défaut 50) | Nombre de résultats |
| `offset` | Nombre (défaut 0) | Décalage pour la pagination |

**Exemple :**
```bash
curl http://localhost:3000/api/feed?severity=critical&limit=10
```

---

### `GET /api/threats`

Retourne les 100 IOCs actifs triés par score.

```bash
curl http://localhost:3000/api/threats
```

---

### `GET /api/cve/:id`

Retourne tous les événements liés à une CVE spécifique.

```bash
curl http://localhost:3000/api/cve/CVE-2024-1234
```

---

### `GET /api/stats`

Statistiques globales : répartition par type, sévérité, source.

```bash
curl http://localhost:3000/api/stats
```

**Exemple de réponse :**
```json
{
  "totalEvents": 1247,
  "urgentEvents": 23,
  "averageScore": 42,
  "byType": {
    "NEWS": 845,
    "IOC": 201,
    "ADVISORY": 87,
    "VULNERABILITY": 114
  },
  "bySeverity": {
    "critical": 23,
    "high": 156,
    "medium": 487
  }
}
```

---

### `GET /api/health`

Santé du système : buffer d'événements, circuit breakers, âge des données.

```bash
curl http://localhost:3000/api/health
```

---

## Cycle de vie des données (TTL Redis)

| Type | TTL | Raison |
|------|-----|--------|
| NEWS | 7 jours | L'actualité passe vite |
| ADVISORY | 30 jours | Les alertes CERT restent pertinentes |
| IOC | 48 heures | Les IPs compromises peuvent être assainies |
| VULNERABILITY | 90 jours | Les CVEs restent pertinentes longtemps |
| RANSOMWARE | 30 jours | Suivi des campagnes actives |

> **Touch on re-see** : Si un IOC réapparaît dans un feed, son TTL Redis est remis à zéro.

---

## Smart Poll Loop

- **Jitter** : ±10% de randomisation sur chaque intervalle (évite les pics de charge)
- **Backoff exponentiel** : après un échec, l'intervalle est multiplié par 2, jusqu'à ×8
- **Circuit breaker** : après 5 échecs consécutifs → cooldown de 30 minutes
- **Staggered start** : les fetchers démarrent avec 5 à 15 secondes de décalage
- **Anti thundering herd** : in-flight promise deduplication dans le cache

---

## Modèle de données `UnifiedThreatEvent`

```typescript
interface UnifiedThreatEvent {
  id: string;                    // Hash MD5 unique (déduplication)
  type: 'NEWS' | 'VULNERABILITY' | 'IOC' | 'ADVISORY' | 'RANSOMWARE';
  source: string;                // Nom de la source
  tier: 1 | 2 | 3 | 4;          // Niveau de crédibilité
  category: string;
  title: string;
  description?: string;
  link?: string;
  timestamp: number;             // Epoch ms
  extractedEntities: {
    cves: string[];              // ["CVE-2024-1234"]
    ips: string[];               // ["1.2.3.4"]
    domains: string[];
    hashes: string[];            // SHA256, MD5, SHA1
    malwareNames: string[];      // ["Emotet", "LockBit"]
    attackTypes: string[];       // ["ransomware", "zero-day"]
  };
  score: number;                 // 0-100
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  isUrgent: boolean;
  correlatedWith?: string[];     // IDs d'événements liés
  ttlCategory: string;
  expiresAt: number;
}
```

---

## Roadmap

- [ ] **Phase 2** : Interface web React (tableau de bord temps réel)
- [ ] **Phase 3** : Alertes Slack/Teams/PagerDuty pour les événements urgents
- [ ] **Phase 4** : Enrichissement EPSS + CVSS depuis l'API NVD
- [ ] **Phase 5** : Score ML basé sur l'historique des menaces
- [ ] **Phase 6** : Export STIX 2.1 pour interopérabilité MISP

---

## Licence

MIT — Voir [LICENSE](LICENSE)

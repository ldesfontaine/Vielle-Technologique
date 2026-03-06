/**
 * Configuration des sources d'intelligence sur les menaces (Threat Intel APIs).
 * Ces sources fournissent des données structurées sur les IOCs, malwares et ransomwares.
 */

export interface ThreatSourceConfig {
  /** Identifiant unique de la source */
  id: string;
  /** Nom affiché */
  name: string;
  /** URL de l'API */
  url: string;
  /** Tier de crédibilité */
  tier: 1 | 2 | 3 | 4;
  /** Type de données fournies */
  dataType: 'ioc' | 'ransomware' | 'malware' | 'vulnerability' | 'enrichment';
  /** Format de réponse */
  format: 'json' | 'csv' | 'csv.gz' | 'text';
  /** Intervalle de polling en secondes */
  intervalSeconds: number;
  /** Clé d'environnement pour l'authentification (optionnel) */
  apiKeyEnv?: string;
  /** Headers HTTP supplémentaires */
  headers?: Record<string, string>;
  /** Limite de requêtes (optionnel, pour les APIs avec quotas) */
  rateLimit?: { maxPerMinute: number };
}

export const THREAT_SOURCES: ThreatSourceConfig[] = [
  // ─── abuse.ch ──────────────────────────────────────────────────────────────
  {
    id: 'feodo-tracker',
    name: 'Feodo Tracker (abuse.ch)',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    tier: 1,
    dataType: 'ioc',
    format: 'json',
    intervalSeconds: 3600,
  },
  {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    tier: 1,
    dataType: 'ioc',
    format: 'json',
    intervalSeconds: 1800,
  },
  {
    id: 'threatfox',
    name: 'ThreatFox (abuse.ch)',
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    tier: 1,
    dataType: 'ioc',
    format: 'json',
    intervalSeconds: 3600,
  },
  {
    id: 'malwarebazaar',
    name: 'MalwareBazaar (abuse.ch)',
    url: 'https://mb-api.abuse.ch/api/v1/',
    tier: 1,
    dataType: 'malware',
    format: 'json',
    intervalSeconds: 3600,
  },

  // ─── Ransomware.live ───────────────────────────────────────────────────────
  {
    id: 'ransomware-live-victims',
    name: 'Ransomware.live - Victims',
    url: 'https://api.ransomware.live/recentvictims',
    tier: 2,
    dataType: 'ransomware',
    format: 'json',
    intervalSeconds: 1800,
  },
  {
    id: 'ransomware-live-groups',
    name: 'Ransomware.live - Groups',
    url: 'https://api.ransomware.live/groups',
    tier: 2,
    dataType: 'ransomware',
    format: 'json',
    intervalSeconds: 86400,
  },

  // ─── MISP / OpenSource Threat Intel ───────────────────────────────────────
  {
    id: 'circl-hashlookup',
    name: 'CIRCL Hash Lookup',
    url: 'https://hashlookup.circl.lu/bulk/md5',
    tier: 2,
    dataType: 'malware',
    format: 'json',
    intervalSeconds: 86400,
  },

  // ─── GitHub Advisory Database ─────────────────────────────────────────────
  {
    id: 'osv-vulnerabilities',
    name: 'OSV Vulnerability Database',
    url: 'https://api.osv.dev/v1/query',
    tier: 1,
    dataType: 'vulnerability',
    format: 'json',
    intervalSeconds: 3600,
  },

  // ─── Phase 2 : Sources gratuites (sans clé API) ──────────────────────────────

  {
    id: 'cisa-kev-json',
    name: 'CISA Known Exploited Vulnerabilities (JSON)',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    tier: 1,
    dataType: 'vulnerability',
    format: 'json',
    intervalSeconds: 3600,
  },
  {
    id: 'epss-scores',
    name: 'EPSS — Exploit Prediction Scoring System',
    url: 'https://epss.cyentia.com/epss_scores-current.csv.gz',
    tier: 1,
    dataType: 'enrichment',
    format: 'csv.gz',
    intervalSeconds: 86400, // 1x par jour (données mises à jour quotidiennement)
  },
  {
    id: 'cveorg-recent',
    name: 'CVE.org — Recent CVEs',
    url: 'https://cveawg.mitre.org/api/cve/?state=PUBLISHED&count_only=false&time_modified.lt=NOW&time_modified.gt=NOW-1D',
    tier: 1,
    dataType: 'vulnerability',
    format: 'json',
    intervalSeconds: 3600,
  },
  {
    id: 'greynoise-community',
    name: 'GreyNoise Community API',
    url: 'https://api.greynoise.io/v3/community/',
    tier: 2,
    dataType: 'enrichment',
    format: 'json',
    intervalSeconds: 86400, // Enrichissement ponctuel, pas de polling bulk
    rateLimit: { maxPerMinute: 2 }, // 50 req/jour ≈ 2/min max burst
  },
  {
    id: 'mitre-attack',
    name: 'MITRE ATT&CK Enterprise (STIX)',
    url: 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    tier: 1,
    dataType: 'enrichment',
    format: 'json',
    intervalSeconds: 604800, // 1x par semaine
  },

  // ─── Phase 2 : Sources avec clé API (optionnelles, skip si pas de clé) ────

  {
    id: 'otx-pulses',
    name: 'AlienVault OTX — Recent Pulses',
    url: 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=1d',
    tier: 2,
    dataType: 'ioc',
    format: 'json',
    intervalSeconds: 1800,
    apiKeyEnv: 'OTX_API_KEY',
  },
  {
    id: 'abuseipdb-blacklist',
    name: 'AbuseIPDB — Blacklist',
    url: 'https://api.abuseipdb.com/api/v2/blacklist',
    tier: 2,
    dataType: 'ioc',
    format: 'json',
    intervalSeconds: 86400, // 1x par jour (quota limité)
    apiKeyEnv: 'ABUSEIPDB_API_KEY',
    rateLimit: { maxPerMinute: 5 },
  },
  {
    id: 'virustotal-trending',
    name: 'VirusTotal — Popular Threat Actors',
    url: 'https://www.virustotal.com/api/v3/popular_threat_actors',
    tier: 1,
    dataType: 'ioc',
    format: 'json',
    intervalSeconds: 86400,
    apiKeyEnv: 'VIRUSTOTAL_API_KEY',
    rateLimit: { maxPerMinute: 4 },
  },
];

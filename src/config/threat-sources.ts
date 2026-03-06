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
  dataType: 'ioc' | 'ransomware' | 'malware' | 'vulnerability';
  /** Format de réponse */
  format: 'json' | 'csv' | 'text';
  /** Intervalle de polling en secondes */
  intervalSeconds: number;
  /** Clé d'environnement pour l'authentification (optionnel) */
  apiKeyEnv?: string;
  /** Headers HTTP supplémentaires */
  headers?: Record<string, string>;
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
];

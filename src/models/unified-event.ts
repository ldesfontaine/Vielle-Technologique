/**
 * Modèle de données unifié pour tous les événements de cybersécurité.
 * Ce modèle commun permet de normaliser les données de sources hétérogènes
 * (RSS, abuse.ch, ransomware.live, etc.) en un format exploitable.
 */

/** Types d'événements supportés */
export type ThreatEventType = 'NEWS' | 'VULNERABILITY' | 'IOC' | 'ADVISORY' | 'RANSOMWARE' | 'TOOL';

/** Niveaux de sévérité */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Catégories de TTL pour le cycle de vie des données */
export type TtlCategory = 'news' | 'advisory' | 'ioc' | 'vulnerability' | 'ransomware' | 'tool';

/** Entités extraites par les extracteurs (le cerveau du système) */
export interface ExtractedEntities {
  /** CVEs identifiées, ex: ["CVE-2024-1234"] */
  cves: string[];
  /** Adresses IP publiques extraites */
  ips: string[];
  /** Noms de domaine malveillants extraits */
  domains: string[];
  /** Hashes de fichiers (MD5, SHA1, SHA256) */
  hashes: string[];
  /** Noms de malwares identifiés */
  malwareNames: string[];
  /** Types d'attaques identifiés */
  attackTypes: string[];
}

/** Modèle unifié pour tous les événements de menace cybersécurité */
export interface UnifiedThreatEvent {
  /** Identifiant unique (hash MD5 pour déduplication) */
  id: string;
  /** Type d'événement */
  type: ThreatEventType;
  /** Nom de la source (ex: "CERT-FR", "BleepingComputer") */
  source: string;
  /** Niveau de crédibilité de la source (1 = plus fiable, 4 = moins fiable) */
  tier: 1 | 2 | 3 | 4;
  /** Catégorie métier de l'événement */
  category: string;
  /** Titre de l'événement */
  title: string;
  /** Description/résumé de l'événement */
  description?: string;
  /** URL source */
  link?: string;
  /** Timestamp de publication en millisecondes (epoch) */
  timestamp: number;
  /** Données brutes pour debug/archivage */
  rawData?: unknown;

  /** Entités extraites automatiquement par les extracteurs */
  extractedEntities: ExtractedEntities;

  /** Score calculé de 0 à 100 (plus élevé = plus urgent) */
  score: number;
  /** Niveau de sévérité dérivé du score */
  severity: SeverityLevel;
  /** Indique si l'événement dépasse le seuil d'urgence (défaut: score >= 70) */
  isUrgent: boolean;

  /** IDs d'autres événements corrélés */
  correlatedWith?: string[];
  /** Données d'enrichissement externes (EPSS, CVSS, etc.) */
  enrichments?: Record<string, unknown>;

  /** Catégorie pour le calcul du TTL Redis */
  ttlCategory: TtlCategory;
  /** Timestamp d'expiration en millisecondes */
  expiresAt: number;
  /** Langue détectée du contenu */
  lang?: string;
}

/** Crée un objet ExtractedEntities vide */
export function emptyEntities(): ExtractedEntities {
  return {
    cves: [],
    ips: [],
    domains: [],
    hashes: [],
    malwareNames: [],
    attackTypes: [],
  };
}

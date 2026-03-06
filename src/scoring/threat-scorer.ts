/**
 * Algorithme de scoring multi-facteurs pour les événements de cybersécurité.
 * Calcule un score de 0 à 100 basé sur la crédibilité de la source,
 * les mots-clés détectés, les entités extraites et les démotions.
 *
 * Formule : Score = Base(tier) + Contenu(keywords) + Urgence(modificateurs) - Bruit(démotions)
 */

import { UnifiedThreatEvent, SeverityLevel, ThreatEventType } from '../models/unified-event.js';
import { ExtractedEntities } from '../models/unified-event.js';

/** Configuration du scoring */
export interface ScoringConfig {
  /** Seuil de score pour isUrgent (défaut: 70) */
  urgentThreshold: number;
}

const DEFAULT_CONFIG: ScoringConfig = {
  urgentThreshold: parseInt(process.env['URGENT_SCORE_THRESHOLD'] ?? '70', 10),
};

// ─── Scores de base par tier ──────────────────────────────────────────────────

const TIER_BASE_SCORES: Record<number, number> = {
  1: 50, // CISA, CERT-FR, ANSSI → très fiable
  2: 35, // BleepingComputer, Krebs → fiable
  3: 20, // Schneier, Talos → expert
  4: 10, // Reddit, blogs → communauté
};

// ─── Modificateurs par type d'événement ─────────────────────────────────────

const TYPE_MODIFIERS: Record<ThreatEventType, number> = {
  ADVISORY: 10,
  VULNERABILITY: 5,
  IOC: 5,
  RANSOMWARE: 15,
  NEWS: 0,
};

// ─── Logique de scoring ───────────────────────────────────────────────────────

/**
 * Calcule le score final d'un événement de menace.
 * @param tier - Tier de crédibilité de la source (1-4)
 * @param type - Type d'événement
 * @param entities - Entités extraites
 * @param keywordScore - Score bonus des mots-clés
 * @param config - Configuration optionnelle du scoring
 * @returns Score final entre 0 et 100
 */
export function calculateScore(
  tier: 1 | 2 | 3 | 4,
  type: ThreatEventType,
  entities: ExtractedEntities,
  keywordScore: number,
  config: ScoringConfig = DEFAULT_CONFIG
): {
  score: number;
  severity: SeverityLevel;
  isUrgent: boolean;
} {
  let score = 0;

  // 1. Score de base selon le tier de la source
  score += TIER_BASE_SCORES[tier] ?? 10;

  // 2. Modificateur selon le type d'événement
  score += TYPE_MODIFIERS[type] ?? 0;

  // 3. Score des mots-clés (déjà calculé par classifyKeywords)
  score += keywordScore;

  // 4. Bonus pour les entités extraites
  if (entities.cves.length > 0) {
    score += 10; // Présence de CVE identifiée
    if (entities.cves.length >= 3) score += 5; // Plusieurs CVEs = campagne
  }

  if (entities.ips.length > 0 || entities.hashes.length > 0) {
    score += 10; // IOCs concrets (IPs/hashes) = événement technique
  }

  if (entities.malwareNames.length > 0) {
    score += 5 * Math.min(entities.malwareNames.length, 3); // Malwares identifiés
  }

  // 5. Limiter le score entre 0 et 100
  score = Math.max(0, Math.min(100, score));

  // 6. Déterminer la sévérité et l'urgence
  const severity = scoreToSeverity(score);
  const isUrgent = score >= config.urgentThreshold;

  return { score, severity, isUrgent };
}

/**
 * Convertit un score numérique en niveau de sévérité.
 * Seuils définis dans les spécifications :
 *   >= 70 → critical
 *   >= 55 → high
 *   >= 40 → medium
 *   >= 25 → low
 *   < 25  → info
 */
export function scoreToSeverity(score: number): SeverityLevel {
  if (score >= 70) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 25) return 'low';
  return 'info';
}

/**
 * Applique un boost de score lors d'une corrélation détectée.
 * Ex: CVE dans un article NEWS qui matche une VULNERABILITY connue.
 * @param currentScore - Score actuel
 * @param correlationType - Type de corrélation
 * @returns Nouveau score (limité à 100)
 */
export function applyCorrelationBoost(
  currentScore: number,
  correlationType: 'cve-match' | 'ioc-match' | 'domain-match'
): number {
  const boosts: Record<string, number> = {
    'cve-match': 15,
    'ioc-match': 20,
    'domain-match': 10,
  };
  return Math.min(100, currentScore + (boosts[correlationType] ?? 10));
}

/**
 * Re-calcule la sévérité d'un événement après mise à jour du score.
 * Mutates l'événement en place.
 */
export function refreshSeverity(
  event: UnifiedThreatEvent,
  config: ScoringConfig = DEFAULT_CONFIG
): void {
  event.severity = scoreToSeverity(event.score);
  event.isUrgent = event.score >= config.urgentThreshold;
}

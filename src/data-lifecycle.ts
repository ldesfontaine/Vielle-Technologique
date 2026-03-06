/**
 * Gestion du cycle de vie des données avec TTL adaptatifs selon le type d'événement.
 * Chaque type d'événement a une durée de vie différente dans le cache Redis.
 *
 * | Type          | TTL Redis   | Raison                                     |
 * |---------------|-------------|--------------------------------------------|
 * | NEWS          | 7 jours     | L'actu passe vite                          |
 * | ADVISORY      | 30 jours    | Alertes CERT restent pertinentes           |
 * | IOC           | 48h         | IPs compromises peuvent être assainies     |
 * | VULNERABILITY | 90 jours    | Vulns restent pertinentes longtemps        |
 * | RANSOMWARE    | 30 jours    | Suivi des campagnes                        |
 */

import { TtlCategory, ThreatEventType } from './models/unified-event.js';
import { touchCache } from './cache/redis.js';

// ─── TTL par catégorie (en secondes) ─────────────────────────────────────────

export const TTL_SECONDS: Record<TtlCategory, number> = {
  news: 7 * 24 * 3600,          // 7 jours = 604800s
  advisory: 30 * 24 * 3600,     // 30 jours = 2592000s
  ioc: 48 * 3600,               // 48 heures = 172800s
  vulnerability: 90 * 24 * 3600, // 90 jours = 7776000s
  ransomware: 30 * 24 * 3600,   // 30 jours = 2592000s
};

/**
 * Mappe le type d'événement vers une catégorie de TTL.
 */
export function getTtlCategory(type: ThreatEventType): TtlCategory {
  const mapping: Record<ThreatEventType, TtlCategory> = {
    NEWS: 'news',
    ADVISORY: 'advisory',
    IOC: 'ioc',
    VULNERABILITY: 'vulnerability',
    RANSOMWARE: 'ransomware',
  };
  return mapping[type];
}

/**
 * Retourne le TTL en secondes pour un type d'événement.
 */
export function getTtlForType(type: ThreatEventType): number {
  return TTL_SECONDS[getTtlCategory(type)];
}

/**
 * Calcule le timestamp d'expiration d'un événement.
 * @param type - Type d'événement
 * @param fromTimestamp - Timestamp de base (défaut: maintenant)
 * @returns Timestamp d'expiration en millisecondes
 */
export function calculateExpiresAt(
  type: ThreatEventType,
  fromTimestamp: number = Date.now()
): number {
  return fromTimestamp + getTtlForType(type) * 1000;
}

/**
 * Réinitialise le TTL d'un IOC qui réapparaît dans un feed.
 * Pattern "touch on re-see" : si un IOC est vu à nouveau, son TTL est remis à zéro.
 * @param eventId - ID de l'événement IOC
 * @param type - Type d'événement (pour déterminer le TTL approprié)
 */
export async function touchOnReSee(eventId: string, type: ThreatEventType): Promise<void> {
  const ttl = getTtlForType(type);
  const cacheKey = `event:${eventId}`;
  await touchCache(cacheKey, ttl);
  console.log(`[lifecycle] TTL remis à zéro pour ${eventId} (${getTtlCategory(type)}, ${ttl}s)`);
}

/**
 * Vérifie si un événement est expiré.
 */
export function isExpired(expiresAt: number): boolean {
  return Date.now() > expiresAt;
}

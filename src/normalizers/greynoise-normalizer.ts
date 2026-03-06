/**
 * Normalizer pour l'API GreyNoise Community.
 * GreyNoise classifie les IPs internet en :
 * - "noise" : scanners de masse, bots bénins
 * - "malicious" : activité confirmée malveillante
 * - "benign" : services légitimes (Shodan, Censys, etc.)
 *
 * Utilisé comme enrichisseur pour les IOCs contenant des IPs.
 * Permet de démoter les faux positifs (IPs bénignes) et booster les vrais threats.
 */

import { setCachedJson, getCachedJson } from '../cache/redis.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GreyNoiseResult {
  ip: string;
  noise: boolean;
  riot: boolean;
  classification: 'benign' | 'malicious' | 'unknown';
  name: string;
  link: string;
  last_seen: string;
  message: string;
}

// ─── Cache ────────────────────────────────────────────────────────────────────

const GN_INDEX_PREFIX = 'idx:greynoise:';
const GN_CACHE_TTL = 24 * 3600; // 24h

/**
 * Stocke un résultat GreyNoise en cache Redis.
 */
export async function cacheGreyNoiseResult(result: GreyNoiseResult): Promise<void> {
  await setCachedJson(`${GN_INDEX_PREFIX}${result.ip}`, {
    classification: result.classification,
    noise: result.noise,
    riot: result.riot,
    name: result.name,
    lastSeen: result.last_seen,
  }, GN_CACHE_TTL);
}

/**
 * Récupère la classification GreyNoise d'une IP depuis le cache.
 */
export async function getGreyNoiseClassification(ip: string): Promise<{
  classification: 'benign' | 'malicious' | 'unknown';
  noise: boolean;
  riot: boolean;
  name: string;
} | null> {
  const cached = await getCachedJson<{
    classification: 'benign' | 'malicious' | 'unknown';
    noise: boolean;
    riot: boolean;
    name: string;
  }>(`${GN_INDEX_PREFIX}${ip}`);

  if (cached && cached !== '__CYBERWATCH_NEG__') {
    return cached;
  }
  return null;
}

/**
 * Normalise la réponse brute GreyNoise Community pour une IP.
 * Retourne les données structurées pour enrichissement.
 */
export function normalizeGreyNoiseResponse(data: unknown): GreyNoiseResult | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as Record<string, unknown>;

  // L'API Community retourne un message d'erreur si IP non trouvée
  if (d['message'] === 'IP not observed scanning the internet or contained in RIOT data set.') {
    return null;
  }

  return {
    ip: String(d['ip'] ?? ''),
    noise: Boolean(d['noise']),
    riot: Boolean(d['riot']),
    classification: (d['classification'] as GreyNoiseResult['classification']) ?? 'unknown',
    name: String(d['name'] ?? ''),
    link: String(d['link'] ?? ''),
    last_seen: String(d['last_seen'] ?? ''),
    message: String(d['message'] ?? ''),
  };
}

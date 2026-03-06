/**
 * Cache Redis avec patterns avancés :
 * - Fallback en mémoire (Map) quand Redis est indisponible
 * - In-flight deduplication (anti thundering herd)
 * - Negative caching avec sentinel __CYBERWATCH_NEG__
 * - Cleanup périodique des entrées expirées
 */

import { Redis } from '@upstash/redis';

// ─── Constantes ───────────────────────────────────────────────────────────────

/** Sentinel pour le negative caching : indique qu'une ressource n'existe pas */
export const NEG_SENTINEL = '__CYBERWATCH_NEG__';

/** TTL du negative cache en secondes */
const NEG_CACHE_TTL = 120;

/** Nombre maximum d'entrées dans le fallback mémoire */
const MAX_MEMORY_ENTRIES = 200;

// ─── Types ────────────────────────────────────────────────────────────────────

interface MemoryCacheEntry {
  value: unknown;
  expiresAt: number;
}

// ─── Client Redis ─────────────────────────────────────────────────────────────

let redisClient: Redis | null = null;

/**
 * Retourne l'instance Redis (lazy initialization).
 * Retourne null si les variables d'environnement ne sont pas configurées.
 */
function getRedis(): Redis | null {
  if (redisClient) return redisClient;

  const url = process.env['UPSTASH_REDIS_REST_URL'];
  const token = process.env['UPSTASH_REDIS_REST_TOKEN'];

  if (!url || !token) {
    return null;
  }

  try {
    redisClient = new Redis({ url, token });
    return redisClient;
  } catch {
    console.warn('[cache] Impossible de créer le client Redis, fallback mémoire activé');
    return null;
  }
}

// ─── Fallback mémoire ─────────────────────────────────────────────────────────

/** Cache mémoire de fallback quand Redis est indisponible */
const memoryCache = new Map<string, MemoryCacheEntry>();

/** Dernier nettoyage du cache mémoire */
let lastMemoryCleanup = Date.now();

/** Nettoie les entrées expirées du cache mémoire (max toutes les 60s) */
function cleanupMemoryCache(): void {
  const now = Date.now();
  if (now - lastMemoryCleanup < 60_000) return;
  lastMemoryCleanup = now;

  for (const [key, entry] of memoryCache.entries()) {
    if (entry.expiresAt < now) {
      memoryCache.delete(key);
    }
  }

  // Limiter la taille maximale (LRU simplifié : supprimer les premières entrées)
  if (memoryCache.size > MAX_MEMORY_ENTRIES) {
    const toDelete = memoryCache.size - MAX_MEMORY_ENTRIES;
    const keys = memoryCache.keys();
    for (let i = 0; i < toDelete; i++) {
      const next = keys.next();
      if (!next.done) {
        memoryCache.delete(next.value);
      }
    }
  }
}

// ─── In-flight deduplication ─────────────────────────────────────────────────

/** Map des requêtes en cours pour éviter le thundering herd */
const inflightRequests = new Map<string, Promise<unknown>>();

// ─── API publique ─────────────────────────────────────────────────────────────

/**
 * Récupère une valeur JSON depuis le cache (Redis ou mémoire).
 * @returns La valeur parsée, null si absente, NEG_SENTINEL si negative cache
 */
export async function getCachedJson<T>(key: string): Promise<T | null | typeof NEG_SENTINEL> {
  cleanupMemoryCache();

  const redis = getRedis();

  if (redis) {
    try {
      const raw = await redis.get<string>(key);
      if (raw === null || raw === undefined) return null;
      if (raw === NEG_SENTINEL) return NEG_SENTINEL;
      if (typeof raw === 'string') {
        return JSON.parse(raw) as T;
      }
      // Upstash peut retourner l'objet déjà parsé
      return raw as unknown as T;
    } catch (err) {
      console.warn(`[cache] Erreur Redis getCachedJson(${key}):`, err);
      // Fallback vers le cache mémoire
    }
  }

  // Fallback mémoire
  const entry = memoryCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    memoryCache.delete(key);
    return null;
  }
  if (entry.value === NEG_SENTINEL) return NEG_SENTINEL;
  return entry.value as T;
}

/**
 * Stocke une valeur JSON dans le cache avec un TTL.
 * @param key - Clé du cache
 * @param value - Valeur à stocker (sera sérialisée en JSON)
 * @param ttlSeconds - Durée de vie en secondes
 */
export async function setCachedJson(
  key: string,
  value: unknown,
  ttlSeconds: number
): Promise<void> {
  cleanupMemoryCache();

  const redis = getRedis();

  if (redis) {
    try {
      const serialized = typeof value === 'string' ? value : JSON.stringify(value);
      await redis.set(key, serialized, { ex: ttlSeconds });
    } catch (err) {
      console.warn(`[cache] Erreur Redis setCachedJson(${key}):`, err);
    }
  }

  // Toujours stocker en mémoire aussi (cohérence lors des fallbacks)
  memoryCache.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
}

/**
 * Stocke un negative sentinel dans le cache.
 * Indique qu'une ressource n'existe pas (évite les requêtes répétées).
 */
export async function setNegativeCache(key: string): Promise<void> {
  await setCachedJson(key, NEG_SENTINEL, NEG_CACHE_TTL);
}

/**
 * Récupère ou calcule une valeur JSON avec :
 * - Negative caching (NEG_SENTINEL)
 * - In-flight deduplication (anti thundering herd)
 * - Fallback mémoire
 *
 * @param key - Clé du cache
 * @param fetcher - Fonction async qui récupère la valeur fraîche
 * @param ttlSeconds - TTL en secondes si la valeur est trouvée
 * @returns La valeur cachée ou fraîchement récupérée, null si non disponible
 */
export async function cachedFetchJson<T>(
  key: string,
  fetcher: () => Promise<T | null>,
  ttlSeconds: number
): Promise<T | null> {
  // 1. Vérifier le cache
  const cached = await getCachedJson<T>(key);
  if (cached === NEG_SENTINEL) return null; // Negative cache hit
  if (cached !== null) return cached;

  // 2. In-flight deduplication : si une requête est déjà en cours, attendre
  const existing = inflightRequests.get(key);
  if (existing) {
    return (await existing) as T | null;
  }

  // 3. Lancer la requête et l'enregistrer comme in-flight
  const fetchPromise = (async () => {
    try {
      const value = await fetcher();

      if (value === null || value === undefined) {
        await setNegativeCache(key);
        return null;
      }

      await setCachedJson(key, value, ttlSeconds);
      return value;
    } catch (err) {
      console.warn(`[cache] Erreur lors du fetch pour ${key}:`, err);
      await setNegativeCache(key);
      return null;
    } finally {
      inflightRequests.delete(key);
    }
  })();

  inflightRequests.set(key, fetchPromise);
  return fetchPromise;
}

/**
 * Invalide une entrée du cache (Redis et mémoire).
 */
export async function invalidateCache(key: string): Promise<void> {
  memoryCache.delete(key);

  const redis = getRedis();
  if (redis) {
    try {
      await redis.del(key);
    } catch (err) {
      console.warn(`[cache] Erreur Redis invalidateCache(${key}):`, err);
    }
  }
}

/**
 * Remet à zéro le TTL d'une clé existante (pattern "touch on re-see").
 * Utilisé pour les IOCs qui réapparaissent dans les feeds.
 */
export async function touchCache(key: string, ttlSeconds: number): Promise<void> {
  const redis = getRedis();
  if (redis) {
    try {
      await redis.expire(key, ttlSeconds);
    } catch {
      // Pas critique si ça échoue, le TTL naturel s'applique
    }
  }

  // Rafraîchir aussi en mémoire
  const entry = memoryCache.get(key);
  if (entry) {
    entry.expiresAt = Date.now() + ttlSeconds * 1000;
  }
}

/**
 * Retourne les statistiques du cache mémoire.
 */
export function getMemoryCacheStats(): { size: number; maxSize: number } {
  return { size: memoryCache.size, maxSize: MAX_MEMORY_ENTRIES };
}

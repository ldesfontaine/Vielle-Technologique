/**
 * Fetcher RSS avec circuit breaker.
 * Récupère le contenu XML des feeds RSS/Atom avec gestion des erreurs,
 * retry et circuit breaker pour éviter de surcharger les sources instables.
 */

import { FeedConfig } from '../config/feeds.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface FetchResult {
  success: boolean;
  xml?: string;
  error?: string;
  statusCode?: number;
}

// ─── Circuit Breaker ──────────────────────────────────────────────────────────

interface CircuitBreakerState {
  failures: number;
  lastFailure: number;
  isOpen: boolean;
  cooldownUntil: number;
}

/** Nombre d'échecs consécutifs avant d'ouvrir le circuit */
const CIRCUIT_BREAK_THRESHOLD = 5;
/** Durée de cooldown en ms (30 minutes) */
const CIRCUIT_COOLDOWN_MS = 30 * 60 * 1000;

const circuitBreakers = new Map<string, CircuitBreakerState>();

function getCircuitBreaker(feedId: string): CircuitBreakerState {
  if (!circuitBreakers.has(feedId)) {
    circuitBreakers.set(feedId, {
      failures: 0,
      lastFailure: 0,
      isOpen: false,
      cooldownUntil: 0,
    });
  }
  return circuitBreakers.get(feedId)!;
}

function recordSuccess(feedId: string): void {
  const cb = getCircuitBreaker(feedId);
  cb.failures = 0;
  cb.isOpen = false;
  cb.cooldownUntil = 0;
}

function recordFailure(feedId: string): void {
  const cb = getCircuitBreaker(feedId);
  cb.failures++;
  cb.lastFailure = Date.now();

  if (cb.failures >= CIRCUIT_BREAK_THRESHOLD) {
    cb.isOpen = true;
    cb.cooldownUntil = Date.now() + CIRCUIT_COOLDOWN_MS;
    console.warn(
      `[rss-fetcher] Circuit ouvert pour ${feedId} après ${cb.failures} échecs. ` +
        `Cooldown jusqu'à ${new Date(cb.cooldownUntil).toISOString()}`
    );
  }
}

function isCircuitOpen(feedId: string): boolean {
  const cb = getCircuitBreaker(feedId);
  if (!cb.isOpen) return false;

  // Vérifier si le cooldown est terminé (half-open)
  if (Date.now() > cb.cooldownUntil) {
    cb.isOpen = false;
    cb.failures = 0;
    console.info(`[rss-fetcher] Circuit semi-ouvert pour ${feedId}, test autorisé`);
    return false;
  }

  return true;
}

// ─── Fetcher ─────────────────────────────────────────────────────────────────

/** Timeout par défaut pour les requêtes HTTP (15 secondes) */
const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Récupère le contenu d'un feed RSS avec circuit breaker.
 * @param feed - Configuration du feed à récupérer
 * @returns Résultat du fetch avec le XML ou une erreur
 */
export async function fetchRssFeed(feed: FeedConfig): Promise<FetchResult> {
  if (isCircuitOpen(feed.id)) {
    const cb = getCircuitBreaker(feed.id);
    return {
      success: false,
      error: `Circuit ouvert jusqu'à ${new Date(cb.cooldownUntil).toISOString()}`,
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const response = await fetch(feed.url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'VeilleCyber/1.0 (cybersecurity monitor; https://github.com/ldesfontaine/vielle-cyber)',
        Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      recordFailure(feed.id);
      return {
        success: false,
        error: `HTTP ${response.status} ${response.statusText}`,
        statusCode: response.status,
      };
    }

    const xml = await response.text();
    recordSuccess(feed.id);

    return { success: true, xml, statusCode: response.status };
  } catch (err) {
    clearTimeout(timeoutId);
    recordFailure(feed.id);

    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: message };
  }
}

/**
 * Retourne l'état des circuit breakers pour le monitoring.
 */
export function getCircuitBreakersStatus(): Record<
  string,
  { isOpen: boolean; failures: number; cooldownUntil?: number }
> {
  const status: Record<string, { isOpen: boolean; failures: number; cooldownUntil?: number }> = {};
  for (const [id, state] of circuitBreakers.entries()) {
    status[id] = {
      isOpen: state.isOpen,
      failures: state.failures,
      ...(state.isOpen ? { cooldownUntil: state.cooldownUntil } : {}),
    };
  }
  return status;
}

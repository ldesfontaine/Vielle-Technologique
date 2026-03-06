/**
 * Smart Poll Loop : boucle de polling intelligente pour les feeds.
 *
 * Fonctionnalités :
 * - Jitter : ±10% de randomisation sur chaque intervalle (évite les pics)
 * - Backoff exponentiel : interval × 2 par échec, max × 8
 * - Circuit breaker : 5 échecs consécutifs → cooldown 30 min
 * - Negative caching : sentinel __CYBERWATCH_NEG__ TTL 120s
 * - Staggered start : décalage de 5-15s entre les fetchers au démarrage
 */

import { FeedConfig, RSS_FEEDS } from './config/feeds.js';
import { THREAT_SOURCES, ThreatSourceConfig } from './config/threat-sources.js';
import { fetchRssFeed } from './fetchers/rss-fetcher.js';
import { fetchThreatSource } from './fetchers/threat-fetcher.js';
import { normalizeRssFeed } from './normalizers/rss-normalizer.js';
import { UnifiedThreatEvent } from './models/unified-event.js';
import { setCachedJson, getCachedJson } from './cache/redis.js';
import { getTtlForType, touchOnReSee } from './data-lifecycle.js';
import { processNewEvent } from './enrichment/cross-correlator.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export type EventCallback = (events: UnifiedThreatEvent[]) => void | Promise<void>;

interface FeedState {
  id: string;
  consecutiveFailures: number;
  lastPollTime: number;
  currentIntervalMs: number;
  baseIntervalMs: number;
  isCircuitOpen: boolean;
  cooldownUntil: number;
}

// ─── Constantes ───────────────────────────────────────────────────────────────

/** Jitter : ±10% de l'intervalle */
const JITTER_FACTOR = 0.1;
/** Multiplicateur de backoff par échec */
const BACKOFF_MULTIPLIER = 2;
/** Maximum de backoff (×8 de l'intervalle de base) */
const MAX_BACKOFF_FACTOR = 8;
/** Nombre d'échecs avant ouverture du circuit */
const CIRCUIT_BREAK_THRESHOLD = 5;
/** Durée du cooldown circuit breaker (30 min) */
const CIRCUIT_COOLDOWN_MS = 30 * 60 * 1000;
/** Délai maximum de stagger au démarrage (ms) */
const MAX_STAGGER_MS = 15_000;
/** Délai minimum de stagger au démarrage (ms) */
const MIN_STAGGER_MS = 5_000;

// ─── Utilitaires ─────────────────────────────────────────────────────────────

/** Applique un jitter de ±10% à un intervalle */
function applyJitter(intervalMs: number): number {
  const jitter = intervalMs * JITTER_FACTOR;
  return intervalMs + (Math.random() * 2 - 1) * jitter;
}

/** Attend un certain nombre de millisecondes */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Gestion des états ────────────────────────────────────────────────────────

function createFeedState(id: string, intervalSeconds: number): FeedState {
  return {
    id,
    consecutiveFailures: 0,
    lastPollTime: 0,
    currentIntervalMs: intervalSeconds * 1000,
    baseIntervalMs: intervalSeconds * 1000,
    isCircuitOpen: false,
    cooldownUntil: 0,
  };
}

function handleSuccess(state: FeedState): void {
  state.consecutiveFailures = 0;
  state.currentIntervalMs = state.baseIntervalMs;
  state.isCircuitOpen = false;
  state.cooldownUntil = 0;
}

function handleFailure(state: FeedState, feedId: string): void {
  state.consecutiveFailures++;

  if (state.consecutiveFailures >= CIRCUIT_BREAK_THRESHOLD) {
    state.isCircuitOpen = true;
    state.cooldownUntil = Date.now() + CIRCUIT_COOLDOWN_MS;
    console.warn(
      `[poll-loop] Circuit ouvert pour ${feedId} (${state.consecutiveFailures} échecs).`
    );
    return;
  }

  // Backoff exponentiel
  const backoffFactor = Math.min(
    Math.pow(BACKOFF_MULTIPLIER, state.consecutiveFailures),
    MAX_BACKOFF_FACTOR
  );
  state.currentIntervalMs = state.baseIntervalMs * backoffFactor;
}

function isCircuitOpen(state: FeedState): boolean {
  if (!state.isCircuitOpen) return false;

  if (Date.now() > state.cooldownUntil) {
    state.isCircuitOpen = false;
    state.consecutiveFailures = 0;
    return false;
  }

  return true;
}

// ─── Stockage des événements ─────────────────────────────────────────────────

/** Clé Redis pour l'index des événements récents */
const RECENT_EVENTS_KEY = 'feed:recent';
/** Nombre maximum d'événements gardés en mémoire/cache */
const MAX_RECENT_EVENTS = 500;

/** Buffer mémoire des événements récents (index rapide) */
const eventBuffer: UnifiedThreatEvent[] = [];

/**
 * Sauvegarde un événement dans le cache Redis et le buffer mémoire.
 * Gère la déduplication et le "touch on re-see" pour les IOCs.
 */
async function saveEvent(event: UnifiedThreatEvent): Promise<boolean> {
  const cacheKey = `event:${event.id}`;

  // Vérifier si l'événement existe déjà
  const existing = await getCachedJson<UnifiedThreatEvent>(cacheKey);
  if (existing && existing !== '__CYBERWATCH_NEG__') {
    // Pattern "touch on re-see" pour les IOCs
    if (event.type === 'IOC') {
      await touchOnReSee(event.id, event.type);
    }
    return false; // Événement déjà connu
  }

  // Enrichissement par corrélation croisée
  await processNewEvent(event);

  // Sauvegarder l'événement
  const ttl = getTtlForType(event.type);
  await setCachedJson(cacheKey, event, ttl);

  // Ajouter au buffer mémoire (limité)
  eventBuffer.unshift(event);
  if (eventBuffer.length > MAX_RECENT_EVENTS) {
    eventBuffer.splice(MAX_RECENT_EVENTS);
  }

  return true; // Nouvel événement
}

// ─── Boucles de polling ───────────────────────────────────────────────────────

/**
 * Boucle de polling pour un feed RSS.
 * S'exécute indéfiniment avec jitter et backoff exponentiel.
 */
async function pollRssFeed(
  feed: FeedConfig,
  state: FeedState,
  onNewEvents: EventCallback
): Promise<never> {
  while (true) {
    if (isCircuitOpen(state)) {
      const waitMs = state.cooldownUntil - Date.now();
      console.info(`[poll-loop] ${feed.id}: circuit ouvert, attente ${Math.round(waitMs / 1000)}s`);
      await sleep(waitMs + 1000);
      continue;
    }

    state.lastPollTime = Date.now();

    try {
      const result = await fetchRssFeed(feed);

      if (!result.success || !result.xml) {
        handleFailure(state, feed.id);
        console.warn(`[poll-loop] ${feed.id}: échec - ${result.error}`);
      } else {
        const events = await normalizeRssFeed(result.xml, feed);
        const newEvents: UnifiedThreatEvent[] = [];

        for (const event of events) {
          const isNew = await saveEvent(event);
          if (isNew) newEvents.push(event);
        }

        handleSuccess(state);

        if (newEvents.length > 0) {
          console.info(`[poll-loop] ${feed.id}: ${newEvents.length} nouveaux événements`);
          await onNewEvents(newEvents);
        }
      }
    } catch (err) {
      handleFailure(state, feed.id);
      console.error(`[poll-loop] ${feed.id}: erreur inattendue:`, err);
    }

    // Attendre l'intervalle avec jitter
    const waitMs = applyJitter(state.currentIntervalMs);
    await sleep(waitMs);
  }
}

/**
 * Boucle de polling pour une source de threat intelligence.
 */
async function pollThreatSource(
  source: ThreatSourceConfig,
  state: FeedState,
  onNewEvents: EventCallback
): Promise<never> {
  while (true) {
    if (isCircuitOpen(state)) {
      const waitMs = state.cooldownUntil - Date.now();
      await sleep(waitMs + 1000);
      continue;
    }

    state.lastPollTime = Date.now();

    try {
      const result = await fetchThreatSource(source);

      if (!result.success) {
        handleFailure(state, source.id);
        console.warn(`[poll-loop] ${source.id}: échec - ${result.error}`);
      } else {
        const newEvents: UnifiedThreatEvent[] = [];

        for (const event of result.events) {
          const isNew = await saveEvent(event);
          if (isNew) newEvents.push(event);
        }

        handleSuccess(state);

        if (newEvents.length > 0) {
          console.info(`[poll-loop] ${source.id}: ${newEvents.length} nouveaux événements`);
          await onNewEvents(newEvents);
        }
      }
    } catch (err) {
      handleFailure(state, source.id);
      console.error(`[poll-loop] ${source.id}: erreur inattendue:`, err);
    }

    const waitMs = applyJitter(state.currentIntervalMs);
    await sleep(waitMs);
  }
}

// ─── API publique ─────────────────────────────────────────────────────────────

/**
 * Démarre toutes les boucles de polling avec staggered start.
 * Chaque fetcher démarre avec un délai aléatoire entre 5 et 15 secondes.
 *
 * @param onNewEvents - Callback appelé quand de nouveaux événements arrivent
 */
export function startPollLoop(onNewEvents: EventCallback): void {
  let staggerDelay = 0;

  // Démarrer les feeds RSS
  for (const feed of RSS_FEEDS) {
    const state = createFeedState(feed.id, feed.intervalSeconds);
    const delay = staggerDelay;
    staggerDelay += MIN_STAGGER_MS + Math.random() * (MAX_STAGGER_MS - MIN_STAGGER_MS);

    setTimeout(() => {
      console.info(`[poll-loop] Démarrage du feed RSS: ${feed.name}`);
      pollRssFeed(feed, state, onNewEvents).catch((err) => {
        console.error(`[poll-loop] Erreur fatale pour ${feed.id}:`, err);
      });
    }, delay);
  }

  // Démarrer les sources threat intel
  for (const source of THREAT_SOURCES) {
    const state = createFeedState(source.id, source.intervalSeconds);
    const delay = staggerDelay;
    staggerDelay += MIN_STAGGER_MS + Math.random() * (MAX_STAGGER_MS - MIN_STAGGER_MS);

    setTimeout(() => {
      console.info(`[poll-loop] Démarrage de la source threat intel: ${source.name}`);
      pollThreatSource(source, state, onNewEvents).catch((err) => {
        console.error(`[poll-loop] Erreur fatale pour ${source.id}:`, err);
      });
    }, delay);
  }

  console.info(
    `[poll-loop] ${RSS_FEEDS.length} feeds RSS + ${THREAT_SOURCES.length} sources threat intel démarrés`
  );
}

/**
 * Retourne les événements récents du buffer mémoire.
 * @param limit - Nombre maximum d'événements à retourner
 */
export function getRecentEvents(limit = 100): UnifiedThreatEvent[] {
  return eventBuffer.slice(0, limit);
}

/**
 * Retourne le buffer complet (pour les requêtes API).
 */
export function getEventBuffer(): UnifiedThreatEvent[] {
  return [...eventBuffer];
}

export { RECENT_EVENTS_KEY };

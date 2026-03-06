/**
 * Fetcher pour les APIs de threat intelligence :
 * - Feodo Tracker (abuse.ch)
 * - URLhaus (abuse.ch)
 * - ThreatFox (abuse.ch)
 * - Ransomware.live
 *
 * Gère l'authentification, les erreurs HTTP et le format des réponses.
 */

import { ThreatSourceConfig } from '../config/threat-sources.js';
import { UnifiedThreatEvent } from '../models/unified-event.js';
import {
  normalizeFeodoEntries,
  normalizeUrlhausEntries,
  normalizeThreatFoxEntries,
  normalizeMalwareBazaarEntries,
} from '../normalizers/abusech-normalizer.js';
import {
  normalizeRansomwareVictims,
  normalizeRansomwareGroups,
} from '../normalizers/ransomware-normalizer.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ThreatFetchResult {
  success: boolean;
  events: UnifiedThreatEvent[];
  error?: string;
  count?: number;
}

// ─── Utilitaires ─────────────────────────────────────────────────────────────

/** Timeout par défaut pour les requêtes (20 secondes) */
const DEFAULT_TIMEOUT_MS = 20_000;

/**
 * Effectue une requête HTTP GET avec timeout et retourne le JSON parsé.
 */
async function fetchJson<T>(url: string, headers?: Record<string, string>): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'VeilleCyber/1.0',
        Accept: 'application/json',
        ...headers,
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    return (await response.json()) as T;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

/**
 * Effectue une requête HTTP POST avec corps JSON.
 */
async function postJson<T>(
  url: string,
  body: unknown,
  headers?: Record<string, string>
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'User-Agent': 'VeilleCyber/1.0',
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...headers,
      },
      body: JSON.stringify(body),
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    return (await response.json()) as T;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

// ─── Fetchers spécialisés ─────────────────────────────────────────────────────

/** Récupère les données du Feodo Tracker */
async function fetchFeodo(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await fetchJson<unknown[]>(source.url);
    const events = normalizeFeodoEntries(
      Array.isArray(data) ? (data as Parameters<typeof normalizeFeodoEntries>[0]) : []
    );
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les URLs malveillantes récentes d'URLhaus */
async function fetchUrlhaus(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await fetchJson<{ urls?: unknown[] }>(source.url);
    const entries = data.urls ?? [];
    const events = normalizeUrlhausEntries(
      Array.isArray(entries) ? (entries as Parameters<typeof normalizeUrlhausEntries>[0]) : []
    );
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les IOCs récents de ThreatFox */
async function fetchThreatFox(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await postJson<{ data?: unknown[] }>(source.url, {
      query: 'get_iocs',
      days: 1,
    });
    const entries = data.data ?? [];
    const events = normalizeThreatFoxEntries(
      Array.isArray(entries) ? (entries as Parameters<typeof normalizeThreatFoxEntries>[0]) : []
    );
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les samples récents de MalwareBazaar */
async function fetchMalwareBazaar(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await postJson<{ data?: unknown[] }>(source.url, {
      query: 'get_recent',
      selector: 100,
    });
    const entries = data.data ?? [];
    const events = normalizeMalwareBazaarEntries(
      Array.isArray(entries)
        ? (entries as Parameters<typeof normalizeMalwareBazaarEntries>[0])
        : []
    );
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les victimes récentes de Ransomware.live */
async function fetchRansomwareVictims(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await fetchJson<unknown[]>(source.url);
    const events = normalizeRansomwareVictims(
      Array.isArray(data) ? (data as Parameters<typeof normalizeRansomwareVictims>[0]) : []
    );
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les groupes actifs de Ransomware.live */
async function fetchRansomwareGroups(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await fetchJson<unknown[]>(source.url);
    const events = normalizeRansomwareGroups(
      Array.isArray(data) ? (data as Parameters<typeof normalizeRansomwareGroups>[0]) : []
    );
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

// ─── Dispatcher principal ─────────────────────────────────────────────────────

/**
 * Récupère les données d'une source de threat intelligence et les normalise.
 * Dispatche vers le fetcher approprié selon l'ID de la source.
 */
export async function fetchThreatSource(
  source: ThreatSourceConfig
): Promise<ThreatFetchResult> {
  console.info(`[threat-fetcher] Fetch ${source.name}...`);

  switch (source.id) {
    case 'feodo-tracker':
      return fetchFeodo(source);
    case 'urlhaus':
      return fetchUrlhaus(source);
    case 'threatfox':
      return fetchThreatFox(source);
    case 'malwarebazaar':
      return fetchMalwareBazaar(source);
    case 'ransomware-live-victims':
      return fetchRansomwareVictims(source);
    case 'ransomware-live-groups':
      return fetchRansomwareGroups(source);
    default:
      return {
        success: false,
        events: [],
        error: `Source ${source.id} non implémentée`,
      };
  }
}

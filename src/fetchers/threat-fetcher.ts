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
import {
  normalizeKevEntries,
  parseAndCacheEpssData,
  normalizeCveOrgEntries,
  normalizeOsvEntries,
} from '../normalizers/vuln-enrichment-normalizer.js';
import { loadAttackBundle, isMitreLoaded } from '../normalizers/mitre-normalizer.js';
import { normalizeOtxPulses } from '../normalizers/otx-normalizer.js';
import { emptyEntities } from '../models/unified-event.js';
import { calculateScore } from '../scoring/threat-scorer.js';
import { calculateExpiresAt } from '../data-lifecycle.js';
import * as crypto from 'crypto';

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

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

/**
 * Token bucket rate limiter simple.
 * Attend si le budget de requêtes est épuisé.
 */
class TokenBucketRateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly maxTokens: number,
    private readonly refillPerMinute: number
  ) {
    this.tokens = maxTokens;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    // Refill tokens
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 60000; // minutes
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillPerMinute);
    this.lastRefill = now;

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }

    // Attendre qu'un token soit disponible
    const waitMs = ((1 - this.tokens) / this.refillPerMinute) * 60000;
    await new Promise(resolve => setTimeout(resolve, waitMs));
    this.tokens = 0;
  }
}

/** Rate limiters par source (lazy init) */
const rateLimiters = new Map<string, TokenBucketRateLimiter>();

function getRateLimiter(source: ThreatSourceConfig): TokenBucketRateLimiter | null {
  if (!source.rateLimit) return null;
  if (!rateLimiters.has(source.id)) {
    rateLimiters.set(source.id, new TokenBucketRateLimiter(
      source.rateLimit.maxPerMinute,
      source.rateLimit.maxPerMinute
    ));
  }
  return rateLimiters.get(source.id)!;
}

// ─── Vérification clé API ─────────────────────────────────────────────────────

/**
 * Vérifie si la clé API requise est présente.
 * Retourne un ThreatFetchResult d'erreur si absente (graceful skip).
 */
function checkApiKey(source: ThreatSourceConfig): ThreatFetchResult | null {
  if (!source.apiKeyEnv) return null;
  const key = process.env[source.apiKeyEnv];
  if (!key) {
    console.info(`[threat-fetcher] ${source.name}: clé API ${source.apiKeyEnv} absente, source ignorée`);
    return { success: true, events: [], count: 0 };
  }
  return null;
}

// ─── Phase 2 : Fetchers spécialisés ──────────────────────────────────────────

/** Récupère le catalogue CISA KEV (JSON) */
async function fetchCisaKev(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await fetchJson<{ vulnerabilities?: unknown[] }>(source.url);
    const events = await normalizeKevEntries(data as Parameters<typeof normalizeKevEntries>[0]);
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère et cache les scores EPSS (CSV.gz) */
async function fetchEpss(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60_000); // 60s timeout pour le gros fichier

    const response = await fetch(source.url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'VeilleCyber/1.0', 'Accept-Encoding': 'gzip' },
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const count = await parseAndCacheEpssData(buffer);

    // EPSS ne produit pas d'événements directs, c'est un enrichisseur
    return { success: true, events: [], count };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les CVEs récentes de CVE.org */
async function fetchCveOrg(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    const data = await fetchJson<{ cveRecords?: unknown[] }>(source.url);
    const events = normalizeCveOrgEntries(data as Parameters<typeof normalizeCveOrgEntries>[0]);
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les vulnérabilités OSV.dev */
async function fetchOsv(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    // OSV.dev attend un POST avec un query body
    // On cherche les vulns récentes tous écosystèmes
    const ecosystems = ['npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'NuGet'];
    const allEvents: UnifiedThreatEvent[] = [];

    for (const ecosystem of ecosystems) {
      try {
        const data = await postJson<{ vulns?: unknown[] }>(source.url, {
          package: { ecosystem },
        });
        const vulns = data.vulns ?? [];
        const events = normalizeOsvEntries(
          vulns as Parameters<typeof normalizeOsvEntries>[0]
        );
        allEvents.push(...events);
      } catch {
        // Certains écosystèmes peuvent ne pas répondre, pas grave
      }
    }

    return { success: true, events: allEvents, count: allEvents.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Charge le bundle MITRE ATT&CK Enterprise (STIX JSON ~20MB, 1x/semaine) */
async function fetchMitreAttack(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  try {
    // Skip si déjà chargé récemment (< 6 jours)
    if (isMitreLoaded()) {
      console.info('[threat-fetcher] MITRE ATT&CK déjà chargé en mémoire, skip');
      return { success: true, events: [], count: 0 };
    }

    console.info('[threat-fetcher] Chargement du bundle MITRE ATT&CK...');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120_000); // 2min timeout

    const response = await fetch(source.url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'VeilleCyber/1.0' },
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const bundle = await response.json();
    loadAttackBundle(bundle as Parameters<typeof loadAttackBundle>[0]);

    // MITRE ne produit pas d'événements directs
    return { success: true, events: [], count: 0 };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Enrichit une IP via l'API GreyNoise Community (pas de polling bulk) */
async function fetchGreyNoiseCommunity(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  // GreyNoise Community est un enrichisseur ponctuel, pas un fetcher bulk.
  // Le polling normal ne fait rien — l'enrichissement se fait dans le cross-correlator.
  // On retourne succès pour ne pas déclencher le circuit breaker.
  return { success: true, events: [], count: 0 };
}

/** Récupère les pulses OTX récentes (nécessite OTX_API_KEY) */
async function fetchOtxPulsesData(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  const skip = checkApiKey(source);
  if (skip) return skip;

  try {
    const apiKey = process.env[source.apiKeyEnv!]!;
    const data = await fetchJson<{ results?: unknown[] }>(source.url, {
      'X-OTX-API-KEY': apiKey,
    });
    const events = normalizeOtxPulses(data as Parameters<typeof normalizeOtxPulses>[0]);
    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère la blacklist AbuseIPDB (nécessite ABUSEIPDB_API_KEY) */
async function fetchAbuseIpdb(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  const skip = checkApiKey(source);
  if (skip) return skip;

  try {
    const apiKey = process.env[source.apiKeyEnv!]!;
    const limiter = getRateLimiter(source);
    if (limiter) await limiter.acquire();

    const data = await fetchJson<{ data?: Array<{ ipAddress?: string; abuseConfidenceScore?: number; countryCode?: string }> }>(
      `${source.url}?confidenceMinimum=90&limit=100`,
      { Key: apiKey, Accept: 'application/json' }
    );

    const entries = data.data ?? [];
    const events: UnifiedThreatEvent[] = entries.map(entry => {
      const ip = entry.ipAddress ?? '';
      const confidence = entry.abuseConfidenceScore ?? 0;
      const id = crypto.createHash('md5').update(`abuseipdb:${ip}`).digest('hex');

      const entities = {
        ...emptyEntities(),
        ips: ip ? [ip] : [],
        attackTypes: ['abuse'],
      };

      const enrichments: Record<string, unknown> = {
        abuseConfidence: confidence,
        country: entry.countryCode,
      };

      const { score, severity, isUrgent } = calculateScore(
        2, 'IOC', entities, Math.round(confidence / 5), enrichments
      );

      return {
        id,
        type: 'IOC' as const,
        source: 'AbuseIPDB',
        tier: 2 as const,
        category: 'threat-intel',
        title: `AbuseIPDB: IP malveillante ${ip} (confiance: ${confidence}%)`,
        description: `IP signalée avec un score de confiance de ${confidence}% — Pays: ${entry.countryCode ?? '?'}`,
        timestamp: Date.now(),
        rawData: entry,
        extractedEntities: entities,
        score,
        severity,
        isUrgent,
        enrichments,
        ttlCategory: 'ioc' as const,
        expiresAt: calculateExpiresAt('IOC'),
      };
    });

    return { success: true, events, count: events.length };
  } catch (err) {
    return { success: false, events: [], error: String(err) };
  }
}

/** Récupère les threat actors populaires VirusTotal (nécessite VIRUSTOTAL_API_KEY) */
async function fetchVirusTotal(source: ThreatSourceConfig): Promise<ThreatFetchResult> {
  const skip = checkApiKey(source);
  if (skip) return skip;

  try {
    const apiKey = process.env[source.apiKeyEnv!]!;
    const limiter = getRateLimiter(source);
    if (limiter) await limiter.acquire();

    const data = await fetchJson<{ data?: Array<{ id?: string; attributes?: Record<string, unknown> }> }>(
      source.url,
      { 'x-apikey': apiKey }
    );

    const entries = data.data ?? [];
    const events: UnifiedThreatEvent[] = entries.slice(0, 50).map(entry => {
      const actorId = entry.id ?? 'unknown';
      const attrs = entry.attributes ?? {};
      const name = String(attrs['name'] ?? actorId);
      const description = String(attrs['description'] ?? '');
      const id = crypto.createHash('md5').update(`vt-actor:${actorId}`).digest('hex');

      const entities = {
        ...emptyEntities(),
        malwareNames: [name.toLowerCase()],
        attackTypes: ['apt'],
      };

      const { score, severity, isUrgent } = calculateScore(1, 'IOC', entities, 15);

      return {
        id,
        type: 'IOC' as const,
        source: 'VirusTotal',
        tier: 1 as const,
        category: 'threat-intel',
        title: `VT Threat Actor: ${name}`,
        description: description.substring(0, 500) || `Acteur de menace suivi par VirusTotal`,
        link: `https://www.virustotal.com/gui/threat-actor/${actorId}`,
        timestamp: Date.now(),
        rawData: entry,
        extractedEntities: entities,
        score,
        severity,
        isUrgent,
        ttlCategory: 'ioc' as const,
        expiresAt: calculateExpiresAt('IOC'),
      };
    });

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

  // Appliquer le rate limiter si configuré
  const limiter = getRateLimiter(source);
  if (limiter) await limiter.acquire();

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

    // Phase 2 — Sources gratuites
    case 'cisa-kev-json':
      return fetchCisaKev(source);
    case 'epss-scores':
      return fetchEpss(source);
    case 'cveorg-recent':
      return fetchCveOrg(source);
    case 'osv-vulnerabilities':
      return fetchOsv(source);
    case 'mitre-attack':
      return fetchMitreAttack(source);
    case 'greynoise-community':
      return fetchGreyNoiseCommunity(source);

    // Phase 2 — Sources avec clé API (graceful skip)
    case 'otx-pulses':
      return fetchOtxPulsesData(source);
    case 'abuseipdb-blacklist':
      return fetchAbuseIpdb(source);
    case 'virustotal-trending':
      return fetchVirusTotal(source);

    default:
      return {
        success: false,
        events: [],
        error: `Source ${source.id} non implémentée`,
      };
  }
}

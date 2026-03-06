/**
 * Normalizer pour les sources de vulnérabilités et d'enrichissement :
 * - CISA KEV (Known Exploited Vulnerabilities) → UnifiedThreatEvent + enrichissement
 * - EPSS (Exploit Prediction Scoring System) → Cache Redis d'enrichissement
 * - CVE.org API → UnifiedThreatEvent de type VULNERABILITY
 * - OSV.dev → UnifiedThreatEvent de type VULNERABILITY
 *
 * Suit le pattern de abusech-normalizer.ts : interfaces typées, generateId(),
 * mapping vers UnifiedThreatEvent, appel calculateScore() + calculateExpiresAt().
 */

import * as crypto from 'crypto';
import * as zlib from 'zlib';
import { UnifiedThreatEvent, emptyEntities } from '../models/unified-event.js';
import { calculateScore } from '../scoring/threat-scorer.js';
import { calculateExpiresAt } from '../data-lifecycle.js';
import { setCachedJson, getCachedJson } from '../cache/redis.js';

// ─── Types ────────────────────────────────────────────────────────────────────

/** CISA KEV entry */
interface KevEntry {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

/** CISA KEV JSON response */
interface KevResponse {
  title?: string;
  catalogVersion?: string;
  vulnerabilities?: KevEntry[];
}

/** CVE.org CVE record (simplified) */
interface CveOrgEntry {
  cveMetadata?: {
    cveId?: string;
    state?: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers?: {
    cna?: {
      title?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      affected?: Array<{
        vendor?: string;
        product?: string;
        versions?: Array<{ version?: string; status?: string }>;
      }>;
      metrics?: Array<{
        cvssV3_1?: {
          baseScore?: number;
          baseSeverity?: string;
          vectorString?: string;
        };
      }>;
      references?: Array<{ url?: string; name?: string }>;
    };
  };
}

/** CVE.org API response */
interface CveOrgResponse {
  cveRecords?: CveOrgEntry[];
  resultsPerPage?: number;
  totalResults?: number;
}

/** OSV.dev vulnerability entry */
interface OsvEntry {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  severity?: Array<{ type?: string; score?: string }>;
  references?: Array<{ type?: string; url?: string }>;
}

/** EPSS CSV parsed line */
interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
}

// ─── Utilitaires ─────────────────────────────────────────────────────────────

function generateId(prefix: string, value: string): string {
  return crypto.createHash('md5').update(`${prefix}:${value}`).digest('hex');
}

function parseDate(dateStr?: string): number {
  if (!dateStr) return Date.now();
  const ts = Date.parse(dateStr);
  return isNaN(ts) ? Date.now() : ts;
}

// ─── CISA KEV ─────────────────────────────────────────────────────────────────

/** Préfixe Redis pour le cache KEV */
const KEV_INDEX_PREFIX = 'idx:kev:';

/**
 * Normalise les entrées CISA KEV en UnifiedThreatEvent[].
 * Chaque CVE activement exploitée = un événement VULNERABILITY à haut score.
 * Stocke aussi l'info en cache Redis pour enrichir d'autres événements.
 */
export async function normalizeKevEntries(data: KevResponse): Promise<UnifiedThreatEvent[]> {
  const entries = data.vulnerabilities ?? [];
  const events: UnifiedThreatEvent[] = [];

  for (const entry of entries) {
    const cveId = entry.cveID ?? '';
    if (!cveId) continue;

    const vendor = entry.vendorProject ?? 'Unknown';
    const product = entry.product ?? 'Unknown';
    const title = `CISA KEV: ${cveId} — ${vendor} ${product}`;
    const id = generateId('kev', cveId);
    const timestamp = parseDate(entry.dateAdded);

    const entities = {
      ...emptyEntities(),
      cves: [cveId.toUpperCase()],
      attackTypes: ['actively-exploited'],
    };

    // Ajouter ransomware si applicable
    if (entry.knownRansomwareCampaignUse === 'Known') {
      entities.attackTypes.push('ransomware');
    }

    const enrichments: Record<string, unknown> = {
      knownExploited: true,
      kevDueDate: entry.dueDate,
      kevRequiredAction: entry.requiredAction,
      ransomwareLinked: entry.knownRansomwareCampaignUse === 'Known',
    };

    const { score, severity, isUrgent } = calculateScore(
      1, 'VULNERABILITY', entities, 30, enrichments
    );

    events.push({
      id,
      type: 'VULNERABILITY',
      source: 'CISA KEV',
      tier: 1,
      category: 'vulnerability',
      title,
      description: entry.shortDescription ?? `${vendor} ${product} — ${entry.vulnerabilityName ?? cveId}`,
      timestamp,
      rawData: entry,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      enrichments,
      ttlCategory: 'vulnerability',
      expiresAt: calculateExpiresAt('VULNERABILITY', timestamp),
    });

    // Stocker dans le cache pour enrichissement croisé
    await setCachedJson(`${KEV_INDEX_PREFIX}${cveId.toUpperCase()}`, {
      knownExploited: true,
      dateAdded: entry.dateAdded,
      dueDate: entry.dueDate,
      ransomwareLinked: entry.knownRansomwareCampaignUse === 'Known',
    }, 90 * 24 * 3600); // TTL 90 jours
  }

  return events;
}

/**
 * Vérifie si une CVE est dans le catalogue CISA KEV (via cache Redis).
 */
export async function isKnownExploited(cveId: string): Promise<boolean> {
  const cached = await getCachedJson<{ knownExploited: boolean }>(`${KEV_INDEX_PREFIX}${cveId.toUpperCase()}`);
  if (cached && cached !== '__CYBERWATCH_NEG__') {
    return cached.knownExploited === true;
  }
  return false;
}

// ─── EPSS ─────────────────────────────────────────────────────────────────────

/** Préfixe Redis pour le cache EPSS */
const EPSS_INDEX_PREFIX = 'idx:epss:';

/**
 * Parse le CSV.gz EPSS et stocke chaque score dans Redis.
 * Format CSV : cve,epss,percentile
 * Retourne le nombre d'entrées traitées.
 */
export async function parseAndCacheEpssData(compressedBuffer: Buffer): Promise<number> {
  // Décompresser le gzip
  const csvBuffer = await new Promise<Buffer>((resolve, reject) => {
    zlib.gunzip(compressedBuffer, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });

  const csvText = csvBuffer.toString('utf-8');
  const lines = csvText.split('\n');
  let count = 0;

  // Trouver la ligne d'en-tête (peut être précédée d'un commentaire)
  let startIndex = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim() ?? '';
    if (line.startsWith('cve,') || line.startsWith('CVE,')) {
      startIndex = i + 1;
      break;
    }
    if (line.startsWith('#')) continue;
    // Si pas de header, essayer de parser quand même
    if (line.match(/^CVE-/i)) {
      startIndex = i;
      break;
    }
  }

  // Parser et stocker chaque entrée (batch)
  const entries: EpssEntry[] = [];
  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i]?.trim();
    if (!line) continue;

    const parts = line.split(',');
    const cve = parts[0]?.trim().toUpperCase() ?? '';
    const epss = parseFloat(parts[1] ?? '0');
    const percentile = parseFloat(parts[2] ?? '0');

    if (cve.startsWith('CVE-') && !isNaN(epss)) {
      entries.push({ cve, epss, percentile });
    }
  }

  // Stocker en Redis — seulement les scores significatifs (EPSS > 0.01)
  // pour éviter de surcharger le cache avec 300k entrées
  const significantEntries = entries.filter(e => e.epss >= 0.01);

  for (const entry of significantEntries) {
    await setCachedJson(
      `${EPSS_INDEX_PREFIX}${entry.cve}`,
      { epss: entry.epss, percentile: entry.percentile },
      25 * 3600 // TTL 25h (données mises à jour toutes les 24h)
    );
    count++;
  }

  console.info(`[epss] ${count} scores EPSS significatifs (≥ 0.01) mis en cache sur ${entries.length} total`);
  return count;
}

/**
 * Récupère le score EPSS d'une CVE depuis le cache Redis.
 * @returns { epss, percentile } ou null si non trouvé
 */
export async function getEpssScore(cveId: string): Promise<{ epss: number; percentile: number } | null> {
  const cached = await getCachedJson<{ epss: number; percentile: number }>(
    `${EPSS_INDEX_PREFIX}${cveId.toUpperCase()}`
  );
  if (cached && cached !== '__CYBERWATCH_NEG__') {
    return cached;
  }
  return null;
}

// ─── CVE.org ──────────────────────────────────────────────────────────────────

/**
 * Normalise les CVEs récentes de l'API CVE.org en UnifiedThreatEvent[].
 */
export function normalizeCveOrgEntries(data: CveOrgResponse): UnifiedThreatEvent[] {
  const records = data.cveRecords ?? [];
  const events: UnifiedThreatEvent[] = [];

  for (const record of records) {
    const cveId = record.cveMetadata?.cveId ?? '';
    if (!cveId) continue;

    const cna = record.containers?.cna;
    const descriptions = cna?.descriptions ?? [];
    const enDesc = descriptions.find(d => d.lang === 'en')?.value
      ?? descriptions[0]?.value ?? '';

    const title = cna?.title ?? `${cveId}: ${enDesc.substring(0, 120)}`;
    const id = generateId('cveorg', cveId);
    const timestamp = parseDate(record.cveMetadata?.datePublished);

    // Extraire le CVSS si disponible
    const cvssMetric = cna?.metrics?.[0]?.cvssV3_1;
    const cvssScore = cvssMetric?.baseScore;
    const cvssSeverity = cvssMetric?.baseSeverity;

    // Extraire les produits affectés
    const affected = cna?.affected ?? [];
    const products = affected.map(a =>
      `${a.vendor ?? 'Unknown'}/${a.product ?? 'Unknown'}`
    );

    const entities = {
      ...emptyEntities(),
      cves: [cveId.toUpperCase()],
    };

    // Bonus CVSS
    let keywordScore = 0;
    if (cvssScore && cvssScore >= 9.0) keywordScore += 20;
    else if (cvssScore && cvssScore >= 7.0) keywordScore += 10;

    const enrichments: Record<string, unknown> = {};
    if (cvssScore) enrichments['cvssScore'] = cvssScore;
    if (cvssSeverity) enrichments['cvssSeverity'] = cvssSeverity;
    if (cvssMetric?.vectorString) enrichments['cvssVector'] = cvssMetric.vectorString;
    if (products.length > 0) enrichments['affectedProducts'] = products;

    const { score, severity, isUrgent } = calculateScore(
      1, 'VULNERABILITY', entities, keywordScore, enrichments
    );

    const refs = cna?.references ?? [];
    const link = refs[0]?.url;

    events.push({
      id,
      type: 'VULNERABILITY',
      source: 'CVE.org',
      tier: 1,
      category: 'vulnerability',
      title,
      description: enDesc.substring(0, 500) || undefined,
      link,
      timestamp,
      rawData: record,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      enrichments: Object.keys(enrichments).length > 0 ? enrichments : undefined,
      ttlCategory: 'vulnerability',
      expiresAt: calculateExpiresAt('VULNERABILITY', timestamp),
    });
  }

  return events;
}

// ─── OSV.dev ──────────────────────────────────────────────────────────────────

/**
 * Normalise les vulnérabilités OSV.dev en UnifiedThreatEvent[].
 */
export function normalizeOsvEntries(entries: OsvEntry[]): UnifiedThreatEvent[] {
  return entries.map((entry) => {
    const osvId = entry.id ?? 'unknown';
    const title = `OSV: ${osvId} — ${entry.summary ?? 'Vulnérabilité open-source'}`;
    const id = generateId('osv', osvId);
    const timestamp = parseDate(entry.published ?? entry.modified);

    // Extraire les CVE aliases
    const cves = (entry.aliases ?? []).filter(a => a.startsWith('CVE-')).map(a => a.toUpperCase());

    // Extraire les packages affectés
    const packages = (entry.affected ?? []).map(a => {
      const pkg = a.package;
      return pkg ? `${pkg.ecosystem ?? '?'}/${pkg.name ?? '?'}` : null;
    }).filter((p): p is string => p !== null);

    const entities = {
      ...emptyEntities(),
      cves,
    };

    // Extraire CVSS si disponible
    const cvssEntry = entry.severity?.find(s => s.type === 'CVSS_V3');
    let keywordScore = 0;
    const enrichments: Record<string, unknown> = {};

    if (cvssEntry?.score) {
      const cvssScore = parseFloat(cvssEntry.score);
      if (!isNaN(cvssScore)) {
        enrichments['cvssScore'] = cvssScore;
        if (cvssScore >= 9.0) keywordScore += 20;
        else if (cvssScore >= 7.0) keywordScore += 10;
      }
    }
    if (packages.length > 0) enrichments['affectedPackages'] = packages;

    const { score, severity, isUrgent } = calculateScore(
      1, 'VULNERABILITY', entities, keywordScore, enrichments
    );

    const link = entry.references?.find(r => r.type === 'ADVISORY' || r.type === 'WEB')?.url;

    return {
      id,
      type: 'VULNERABILITY' as const,
      source: 'OSV.dev',
      tier: 1 as const,
      category: 'vulnerability',
      title,
      description: entry.details?.substring(0, 500) ?? entry.summary,
      link,
      timestamp,
      rawData: entry,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      enrichments: Object.keys(enrichments).length > 0 ? enrichments : undefined,
      ttlCategory: 'vulnerability' as const,
      expiresAt: calculateExpiresAt('VULNERABILITY', timestamp),
    };
  });
}

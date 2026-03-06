/**
 * Normalizer pour AlienVault OTX (Open Threat Exchange).
 * Transforme les "pulses" OTX en UnifiedThreatEvent[].
 * Chaque pulse contient des IOCs multi-types (IPs, domaines, hashes, CVEs, URLs).
 * Source optionnelle : nécessite une clé API (OTX_API_KEY).
 */

import * as crypto from 'crypto';
import { UnifiedThreatEvent, emptyEntities } from '../models/unified-event.js';
import { calculateScore } from '../scoring/threat-scorer.js';
import { calculateExpiresAt } from '../data-lifecycle.js';

// ─── Types OTX ────────────────────────────────────────────────────────────────

interface OtxIndicator {
  id?: number;
  indicator?: string;
  type?: string; // 'IPv4' | 'domain' | 'hostname' | 'URL' | 'FileHash-MD5' | 'FileHash-SHA1' | 'FileHash-SHA256' | 'CVE'
  title?: string;
  description?: string;
}

interface OtxPulse {
  id?: string;
  name?: string;
  description?: string;
  author_name?: string;
  created?: string;
  modified?: string;
  indicators?: OtxIndicator[];
  tags?: string[];
  adversary?: string;
  targeted_countries?: string[];
  attack_ids?: Array<{ id?: string; name?: string }>;
  malware_families?: string[];
  references?: string[];
  tlp?: string;
}

interface OtxResponse {
  results?: OtxPulse[];
  count?: number;
  next?: string;
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

// ─── Normalizer ──────────────────────────────────────────────────────────────

/**
 * Normalise les pulses OTX en UnifiedThreatEvent[].
 * Chaque pulse = un événement IOC contenant tous les indicateurs associés.
 */
export function normalizeOtxPulses(data: OtxResponse): UnifiedThreatEvent[] {
  const pulses = data.results ?? [];
  const events: UnifiedThreatEvent[] = [];

  for (const pulse of pulses) {
    const pulseId = pulse.id ?? '';
    if (!pulseId) continue;

    const name = pulse.name ?? 'OTX Pulse sans nom';
    const title = `OTX: ${name}`;
    const id = generateId('otx', pulseId);
    const timestamp = parseDate(pulse.created ?? pulse.modified);

    // Extraire les IOCs par type
    const entities = { ...emptyEntities() };
    const indicators = pulse.indicators ?? [];

    for (const indicator of indicators) {
      const value = indicator.indicator ?? '';
      if (!value) continue;

      switch (indicator.type) {
        case 'IPv4':
        case 'IPv6':
          entities.ips.push(value);
          break;
        case 'domain':
        case 'hostname':
          entities.domains.push(value);
          break;
        case 'FileHash-MD5':
        case 'FileHash-SHA1':
        case 'FileHash-SHA256':
          entities.hashes.push(value.toLowerCase());
          break;
        case 'CVE':
          entities.cves.push(value.toUpperCase());
          break;
        case 'URL':
          // Extraire le domaine de l'URL
          try {
            entities.domains.push(new URL(value).hostname);
          } catch {
            // URL malformée
          }
          break;
      }
    }

    // Déduplication
    entities.ips = [...new Set(entities.ips)].slice(0, 50);
    entities.domains = [...new Set(entities.domains)].slice(0, 50);
    entities.hashes = [...new Set(entities.hashes)].slice(0, 50);
    entities.cves = [...new Set(entities.cves)];

    // Malwares et attack types
    if (pulse.malware_families && pulse.malware_families.length > 0) {
      entities.malwareNames = pulse.malware_families.map(m => m.toLowerCase());
    }
    if (pulse.adversary) {
      entities.attackTypes.push('apt');
    }
    if (pulse.attack_ids) {
      for (const attack of pulse.attack_ids) {
        if (attack.id) entities.attackTypes.push(attack.id);
      }
    }

    // Bonus scoring
    let keywordScore = 0;
    if (indicators.length >= 50) keywordScore += 15;   // Pulse riche
    else if (indicators.length >= 10) keywordScore += 10;
    if (pulse.adversary) keywordScore += 10;            // APT identifié
    if (pulse.tags?.some(t => t.toLowerCase().includes('apt'))) keywordScore += 10;

    const { score, severity, isUrgent } = calculateScore(
      2, 'IOC', entities, keywordScore
    );

    const enrichments: Record<string, unknown> = {};
    if (pulse.adversary) enrichments['adversary'] = pulse.adversary;
    if (pulse.targeted_countries && pulse.targeted_countries.length > 0) {
      enrichments['targetedCountries'] = pulse.targeted_countries;
    }
    if (pulse.tlp) enrichments['tlp'] = pulse.tlp;

    events.push({
      id,
      type: 'IOC',
      source: `OTX (${pulse.author_name ?? 'AlienVault'})`,
      tier: 2,
      category: 'threat-intel',
      title,
      description: pulse.description?.substring(0, 500) ?? `${indicators.length} indicateurs`,
      link: `https://otx.alienvault.com/pulse/${pulseId}`,
      timestamp,
      rawData: pulse,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      enrichments: Object.keys(enrichments).length > 0 ? enrichments : undefined,
      ttlCategory: 'ioc',
      expiresAt: calculateExpiresAt('IOC', timestamp),
    });
  }

  return events;
}

/**
 * Normalizer pour ransomware.live.
 * Transforme les victimes et groupes de ransomware en UnifiedThreatEvent.
 * ransomware.live est une source communautaire qui suit les revendications
 * des groupes de ransomware sur leurs sites .onion (data leak sites).
 */

import * as crypto from 'crypto';
import { UnifiedThreatEvent, emptyEntities } from '../models/unified-event.js';
import { calculateScore } from '../scoring/threat-scorer.js';
import { calculateExpiresAt } from '../data-lifecycle.js';

// ─── Types ransomware.live ────────────────────────────────────────────────────

interface RansomwareVictim {
  victim?: string;
  group?: string;
  country?: string;
  activity?: string;
  published?: string;
  post_title?: string;
  description?: string;
  website?: string;
  discovered?: string;
}

interface RansomwareGroup {
  name?: string;
  description?: string;
  count?: number;
  locations?: string[];
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

// ─── Normalizer victimes ──────────────────────────────────────────────────────

/**
 * Normalise une victime de ransomware en UnifiedThreatEvent.
 * Chaque revendication publiée par un groupe = un événement RANSOMWARE.
 */
export function normalizeRansomwareVictim(victim: RansomwareVictim): UnifiedThreatEvent {
  const victimName = victim.victim ?? 'Victime inconnue';
  const groupName = victim.group ?? 'Groupe inconnu';
  const country = victim.country ?? '?';
  const sector = victim.activity ?? 'secteur inconnu';

  const title = `Ransomware ${groupName}: ${victimName} (${country})`;
  const id = generateId(
    'ransomware-victim',
    `${groupName}:${victimName}:${victim.published ?? Date.now()}`
  );
  const timestamp = parseDate(victim.published ?? victim.discovered);

  const description = [
    victim.post_title ? `"${victim.post_title}"` : null,
    `Secteur: ${sector}`,
    victim.website ? `Site: ${victim.website}` : null,
    victim.description ? victim.description.substring(0, 200) : null,
  ]
    .filter(Boolean)
    .join(' - ');

  const entities = {
    ...emptyEntities(),
    malwareNames: [groupName.toLowerCase()],
    attackTypes: ['ransomware', 'data-breach'],
    domains: victim.website ? [extractDomain(victim.website)] : [],
  };

  // Score élevé car c'est une attaque ransomware confirmée
  const { score, severity, isUrgent } = calculateScore(
    2, // Ransomware.live est tier 2
    'RANSOMWARE',
    entities,
    25 // Bonus ransomware fixe
  );

  return {
    id,
    type: 'RANSOMWARE' as const,
    source: 'Ransomware.live',
    tier: 2 as const,
    category: 'ransomware',
    title,
    description: description || undefined,
    link: victim.website,
    timestamp,
    rawData: victim,
    extractedEntities: entities,
    score,
    severity,
    isUrgent,
    ttlCategory: 'ransomware' as const,
    expiresAt: calculateExpiresAt('RANSOMWARE', timestamp),
  };
}

/**
 * Normalise un groupe de ransomware actif en événement de contexte.
 */
export function normalizeRansomwareGroup(group: RansomwareGroup): UnifiedThreatEvent {
  const name = group.name ?? 'Groupe inconnu';
  const count = group.count ?? 0;

  const title = `Groupe Ransomware actif: ${name} (${count} victimes)`;
  const id = generateId('ransomware-group', name);
  const timestamp = Date.now();

  const entities = {
    ...emptyEntities(),
    malwareNames: [name.toLowerCase()],
    attackTypes: ['ransomware'],
  };

  const { score, severity, isUrgent } = calculateScore(2, 'RANSOMWARE', entities, 20);

  return {
    id,
    type: 'RANSOMWARE' as const,
    source: 'Ransomware.live',
    tier: 2 as const,
    category: 'ransomware',
    title,
    description: group.description?.substring(0, 300),
    timestamp,
    rawData: group,
    extractedEntities: entities,
    score,
    severity,
    isUrgent,
    ttlCategory: 'ransomware' as const,
    expiresAt: calculateExpiresAt('RANSOMWARE', timestamp),
  };
}

/**
 * Normalise un tableau de victimes ransomware.
 */
export function normalizeRansomwareVictims(
  victims: RansomwareVictim[]
): UnifiedThreatEvent[] {
  return victims.map(normalizeRansomwareVictim);
}

/**
 * Normalise un tableau de groupes ransomware.
 */
export function normalizeRansomwareGroups(
  groups: RansomwareGroup[]
): UnifiedThreatEvent[] {
  return groups.map(normalizeRansomwareGroup);
}

// ─── Utilitaire ───────────────────────────────────────────────────────────────

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

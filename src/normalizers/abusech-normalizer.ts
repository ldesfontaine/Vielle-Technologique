/**
 * Normalizer pour les APIs abuse.ch :
 * - Feodo Tracker (IPs de C2 botnets)
 * - URLhaus (URLs malveillantes)
 * - ThreatFox (IOCs multi-types)
 * - MalwareBazaar (samples de malwares)
 *
 * Transforme les JSON bruts en UnifiedThreatEvent standardisés.
 */

import * as crypto from 'crypto';
import { UnifiedThreatEvent, emptyEntities } from '../models/unified-event.js';
import { calculateScore } from '../scoring/threat-scorer.js';
import { calculateExpiresAt } from '../data-lifecycle.js';

// ─── Types des réponses abuse.ch ──────────────────────────────────────────────

interface FeodoEntry {
  ip_address?: string;
  port?: number;
  status?: string;
  malware?: string;
  first_seen?: string;
  last_online?: string;
  country?: string;
}

interface UrlhausEntry {
  id?: string;
  url?: string;
  url_status?: string;
  date_added?: string;
  threat?: string;
  tags?: string[];
  urlhaus_reference?: string;
}

interface ThreatFoxEntry {
  id?: string;
  ioc_value?: string;
  ioc_type?: string;
  threat_type?: string;
  malware?: string;
  first_seen?: string;
  confidence_level?: number;
  tags?: string[];
}

interface MalwareBazaarEntry {
  sha256_hash?: string;
  md5_hash?: string;
  sha1_hash?: string;
  file_name?: string;
  file_type?: string;
  signature?: string;
  first_seen?: string;
  tags?: string[];
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

// ─── Feodo Tracker ────────────────────────────────────────────────────────────

/**
 * Normalise les entrées du Feodo Tracker (IPs de C2 botnet).
 * Les entrées actives sont prioritaires.
 */
export function normalizeFeodoEntries(entries: FeodoEntry[]): UnifiedThreatEvent[] {
  return entries.map((entry) => {
    const ip = entry.ip_address ?? 'unknown';
    const malware = entry.malware ?? 'unknown';
    const title = `IOC Feodo: ${malware} C2 @ ${ip}:${entry.port ?? '?'}`;
    const id = generateId('feodo', `${ip}:${entry.port ?? '0'}`);
    const timestamp = parseDate(entry.first_seen);

    const entities = {
      ...emptyEntities(),
      ips: ip !== 'unknown' ? [ip] : [],
      malwareNames: malware !== 'unknown' ? [malware.toLowerCase()] : [],
      attackTypes: ['botnet', 'c2'],
    };

    // Boost si le C2 est encore actif
    const activeBonus = entry.status === 'online' ? 20 : 0;

    const { score, severity, isUrgent } = calculateScore(
      1, // Feodo est tier 1
      'IOC',
      entities,
      activeBonus
    );

    return {
      id,
      type: 'IOC' as const,
      source: 'Feodo Tracker (abuse.ch)',
      tier: 1 as const,
      category: 'threat-intel',
      title,
      description: `Serveur C2 ${malware} - Pays: ${entry.country ?? 'inconnu'} - Statut: ${entry.status ?? 'inconnu'}`,
      timestamp,
      rawData: entry,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      ttlCategory: 'ioc' as const,
      expiresAt: calculateExpiresAt('IOC', timestamp),
    };
  });
}

// ─── URLhaus ──────────────────────────────────────────────────────────────────

/**
 * Normalise les entrées URLhaus (URLs malveillantes).
 */
export function normalizeUrlhausEntries(entries: UrlhausEntry[]): UnifiedThreatEvent[] {
  return entries.map((entry) => {
    const url = entry.url ?? 'unknown';
    const threat = entry.threat ?? 'malware';
    const title = `IOC URLhaus: ${threat} @ ${url.substring(0, 80)}`;
    const id = generateId('urlhaus', entry.id ?? url);
    const timestamp = parseDate(entry.date_added);

    // Extraire le domaine de l'URL
    let domain = '';
    try {
      domain = new URL(url).hostname;
    } catch {
      // URL malformée, pas grave
    }

    const entities = {
      ...emptyEntities(),
      domains: domain ? [domain] : [],
      attackTypes: [threat.toLowerCase().replace(/\s+/g, '-')],
    };

    const { score, severity, isUrgent } = calculateScore(1, 'IOC', entities, 15);

    return {
      id,
      type: 'IOC' as const,
      source: 'URLhaus (abuse.ch)',
      tier: 1 as const,
      category: 'threat-intel',
      title,
      description: `URL malveillante - Tags: ${(entry.tags ?? []).join(', ')} - Statut: ${entry.url_status ?? 'inconnu'}`,
      link: entry.urlhaus_reference,
      timestamp,
      rawData: entry,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      ttlCategory: 'ioc' as const,
      expiresAt: calculateExpiresAt('IOC', timestamp),
    };
  });
}

// ─── ThreatFox ────────────────────────────────────────────────────────────────

/**
 * Normalise les entrées ThreatFox (IOCs multi-types).
 */
export function normalizeThreatFoxEntries(entries: ThreatFoxEntry[]): UnifiedThreatEvent[] {
  return entries.map((entry) => {
    const iocValue = entry.ioc_value ?? 'unknown';
    const iocType = entry.ioc_type ?? 'unknown';
    const malware = entry.malware ?? 'unknown';
    const title = `IOC ThreatFox: ${malware} - ${iocType}: ${iocValue.substring(0, 60)}`;
    const id = generateId('threatfox', entry.id ?? iocValue);
    const timestamp = parseDate(entry.first_seen);

    // Classifier le type d'IOC
    const entities = { ...emptyEntities() };
    if (iocType === 'ip:port') {
      const ipPart = iocValue.split(':')[0];
      if (ipPart) entities.ips = [ipPart];
    } else if (iocType === 'domain' || iocType === 'url') {
      entities.domains = [iocValue];
    } else if (iocType === 'md5_hash') {
      entities.hashes = [iocValue.toLowerCase()];
    } else if (iocType === 'sha256_hash') {
      entities.hashes = [iocValue.toLowerCase()];
    }

    if (malware !== 'unknown') {
      entities.malwareNames = [malware.toLowerCase()];
    }
    entities.attackTypes = [entry.threat_type ?? 'unknown'];

    // Bonus selon le niveau de confiance
    const confidenceBonus = Math.round(((entry.confidence_level ?? 50) / 100) * 20);

    const { score, severity, isUrgent } = calculateScore(
      1, 'IOC', entities, confidenceBonus
    );

    return {
      id,
      type: 'IOC' as const,
      source: 'ThreatFox (abuse.ch)',
      tier: 1 as const,
      category: 'threat-intel',
      title,
      description: `Tags: ${(entry.tags ?? []).join(', ')} - Confiance: ${entry.confidence_level ?? '?'}%`,
      timestamp,
      rawData: entry,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      ttlCategory: 'ioc' as const,
      expiresAt: calculateExpiresAt('IOC', timestamp),
    };
  });
}

// ─── MalwareBazaar ────────────────────────────────────────────────────────────

/**
 * Normalise les entrées MalwareBazaar (samples de malwares).
 */
export function normalizeMalwareBazaarEntries(
  entries: MalwareBazaarEntry[]
): UnifiedThreatEvent[] {
  return entries.map((entry) => {
    const sha256 = entry.sha256_hash ?? '';
    const signature = entry.signature ?? 'Malware inconnu';
    const title = `Malware: ${signature} (${entry.file_type ?? '?'})`;
    const id = generateId('malwarebazaar', sha256 || (entry.md5_hash ?? title));
    const timestamp = parseDate(entry.first_seen);

    const hashes = [sha256, entry.sha1_hash, entry.md5_hash]
      .filter((h): h is string => !!h)
      .map((h) => h.toLowerCase());

    const entities = {
      ...emptyEntities(),
      hashes,
      malwareNames: [signature.toLowerCase()],
      attackTypes: ['malware'],
    };

    const { score, severity, isUrgent } = calculateScore(1, 'IOC', entities, 10);

    return {
      id,
      type: 'IOC' as const,
      source: 'MalwareBazaar (abuse.ch)',
      tier: 1 as const,
      category: 'threat-intel',
      title,
      description: `Fichier: ${entry.file_name ?? 'inconnu'} - Tags: ${(entry.tags ?? []).join(', ')}`,
      timestamp,
      rawData: entry,
      extractedEntities: entities,
      score,
      severity,
      isUrgent,
      ttlCategory: 'ioc' as const,
      expiresAt: calculateExpiresAt('IOC', timestamp),
    };
  });
}

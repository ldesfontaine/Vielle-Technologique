/**
 * Normalizer RSS : transforme les items RSS/Atom XML en UnifiedThreatEvent.
 * Supporte à la fois le format RSS 2.0 (balise <item>) et Atom (<entry>).
 */

import * as crypto from 'crypto';
import * as xml2js from 'xml2js';
import { UnifiedThreatEvent, ThreatEventType, emptyEntities } from '../models/unified-event.js';
import { FeedConfig } from '../config/feeds.js';
import { extractCves } from '../extractors/cve-extractor.js';
import { extractIps, extractDomains, extractHashes } from '../extractors/ioc-extractor.js';
import { classifyKeywords } from '../extractors/keyword-classifier.js';
import { calculateScore } from '../scoring/threat-scorer.js';
import { getTtlCategory, calculateExpiresAt } from '../data-lifecycle.js';

// ─── Types internes ───────────────────────────────────────────────────────────

interface RssItem {
  title?: string[];
  link?: string[];
  description?: string[];
  summary?: string[];
  pubDate?: string[];
  published?: string[];
  updated?: string[];
  id?: string[];
  guid?: string[];
  content?: string[];
}

interface ParsedFeed {
  rss?: { channel?: [{ item?: RssItem[] }] };
  feed?: { entry?: RssItem[] };
}

// ─── Utilitaires ─────────────────────────────────────────────────────────────

/** Extrait le premier élément d'un tableau ou retourne une valeur par défaut */
function first(arr?: string[], fallback = ''): string {
  return arr?.[0] ?? fallback;
}

/** Nettoie le HTML des balises pour obtenir du texte brut */
function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

/** Parse une date en timestamp ms, retourne Date.now() si invalide */
function parseDate(dateStr: string): number {
  if (!dateStr) return Date.now();
  const ts = Date.parse(dateStr);
  return isNaN(ts) ? Date.now() : ts;
}

/** Génère un ID MD5 unique pour déduplication */
function generateId(title: string, link: string, source: string): string {
  const hash = crypto.createHash('md5');
  hash.update(`${source}:${title}:${link}`);
  return hash.digest('hex');
}

/** Détermine le type d'événement en fonction de la catégorie du feed */
function categoryToType(category: FeedConfig['category']): ThreatEventType {
  const mapping: Record<FeedConfig['category'], ThreatEventType> = {
    advisory: 'ADVISORY',
    news: 'NEWS',
    vulnerability: 'VULNERABILITY',
    'threat-intel': 'IOC',
    ransomware: 'RANSOMWARE',
  };
  return mapping[category];
}

// ─── Parser XML ───────────────────────────────────────────────────────────────

/**
 * Parse le XML d'un feed RSS/Atom et retourne les items bruts.
 */
async function parseFeedXml(xml: string): Promise<RssItem[]> {
  const parser = new xml2js.Parser({ explicitArray: true, mergeAttrs: true });

  let parsed: ParsedFeed;
  try {
    parsed = await parser.parseStringPromise(xml) as ParsedFeed;
  } catch (err) {
    throw new Error(`Erreur de parsing XML: ${err}`);
  }

  // Format RSS 2.0
  if (parsed.rss?.channel?.[0]?.item) {
    return parsed.rss.channel[0].item;
  }

  // Format Atom
  if (parsed.feed?.entry) {
    return parsed.feed.entry;
  }

  return [];
}

// ─── Normalizer principal ─────────────────────────────────────────────────────

/**
 * Normalise un item RSS brut en UnifiedThreatEvent.
 */
function normalizeItem(item: RssItem, feed: FeedConfig): UnifiedThreatEvent {
  const title = stripHtml(first(item.title));
  const link = first(item.link) || first(item.id) || first(item.guid);
  const description = stripHtml(
    first(item.description) || first(item.summary) || first(item.content)
  );
  const dateStr =
    first(item.pubDate) || first(item.published) || first(item.updated);

  const timestamp = parseDate(dateStr);
  const id = generateId(title, link, feed.name);
  const type = categoryToType(feed.category);

  // Analyse du contenu complet
  const fullText = `${title} ${description}`;

  const cves = extractCves(fullText);
  const ips = extractIps(fullText);
  const domains = extractDomains(fullText);
  const hashes = extractHashes(fullText);
  const classification = classifyKeywords(fullText);

  const entities = {
    ...emptyEntities(),
    cves,
    ips,
    domains,
    hashes,
    malwareNames: classification.malwareNames,
    attackTypes: classification.attackTypes,
  };

  const { score, severity, isUrgent } = calculateScore(
    feed.tier,
    type,
    entities,
    classification.totalKeywordScore
  );

  const ttlCategory = getTtlCategory(type);
  const expiresAt = calculateExpiresAt(type, timestamp);

  return {
    id,
    type,
    source: feed.name,
    tier: feed.tier,
    category: feed.category,
    title,
    description: description || undefined,
    link: link || undefined,
    timestamp,
    rawData: item,
    extractedEntities: entities,
    score,
    severity,
    isUrgent,
    ttlCategory,
    expiresAt,
    lang: feed.lang,
  };
}

/**
 * Normalise un feed RSS complet (XML) en tableau d'UnifiedThreatEvent.
 * @param xml - Contenu XML du feed
 * @param feed - Configuration du feed source
 * @returns Tableau d'événements normalisés
 */
export async function normalizeRssFeed(
  xml: string,
  feed: FeedConfig
): Promise<UnifiedThreatEvent[]> {
  const items = await parseFeedXml(xml);
  return items
    .map((item) => normalizeItem(item, feed))
    .filter((event) => event.title.length > 0);
}

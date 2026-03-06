/**
 * Corrélateur croisé : détecte les liens entre événements de sources différentes.
 *
 * Logique :
 * 1. Quand un nouvel événement arrive, extraire ses entités (CVEs, IPs, etc.)
 * 2. Chercher dans le cache si ces entités sont déjà connues
 * 3. Lier les événements corrélés et booster leurs scores
 *
 * Exemples de corrélations :
 * - CVE dans un article NEWS ↔ CVE dans une VULNERABILITY → lien + boost
 * - IP dans un article NEWS ↔ IOC Feodo actif → lien + boost
 */

import { UnifiedThreatEvent } from '../models/unified-event.js';
import { getCachedJson, setCachedJson } from '../cache/redis.js';
import { applyCorrelationBoost, refreshSeverity } from '../scoring/threat-scorer.js';
import { getEpssScore, isKnownExploited } from '../normalizers/vuln-enrichment-normalizer.js';
import { lookupTTPs, isMitreLoaded } from '../normalizers/mitre-normalizer.js';
import { getGreyNoiseClassification } from '../normalizers/greynoise-normalizer.js';

// ─── Constantes ───────────────────────────────────────────────────────────────

/** Préfixe des clés d'index CVE dans Redis */
const CVE_INDEX_PREFIX = 'idx:cve:';
/** Préfixe des clés d'index IP dans Redis */
const IP_INDEX_PREFIX = 'idx:ip:';
/** Préfixe des clés d'index domaine dans Redis */
const DOMAIN_INDEX_PREFIX = 'idx:domain:';
/** TTL des index de corrélation (7 jours) */
const INDEX_TTL = 7 * 24 * 3600;

// ─── Types ────────────────────────────────────────────────────────────────────

interface EntityIndex {
  /** IDs des événements contenant cette entité */
  eventIds: string[];
}

// ─── Indexation ───────────────────────────────────────────────────────────────

/**
 * Indexe les entités d'un événement dans Redis pour les corrélations futures.
 * Crée des index inversés : entité → liste d'événements.
 */
export async function indexEventEntities(event: UnifiedThreatEvent): Promise<void> {
  const { cves, ips, domains } = event.extractedEntities;

  // Indexer les CVEs
  for (const cve of cves) {
    const key = `${CVE_INDEX_PREFIX}${cve}`;
    const existing = (await getCachedJson<EntityIndex>(key)) ?? { eventIds: [] };
    if (existing !== '__CYBERWATCH_NEG__' && !existing.eventIds.includes(event.id)) {
      existing.eventIds.push(event.id);
      await setCachedJson(key, existing, INDEX_TTL);
    }
  }

  // Indexer les IPs
  for (const ip of ips) {
    const key = `${IP_INDEX_PREFIX}${ip}`;
    const existing = (await getCachedJson<EntityIndex>(key)) ?? { eventIds: [] };
    if (existing !== '__CYBERWATCH_NEG__' && !existing.eventIds.includes(event.id)) {
      existing.eventIds.push(event.id);
      await setCachedJson(key, existing, INDEX_TTL);
    }
  }

  // Indexer les domaines
  for (const domain of domains) {
    const key = `${DOMAIN_INDEX_PREFIX}${domain}`;
    const existing = (await getCachedJson<EntityIndex>(key)) ?? { eventIds: [] };
    if (existing !== '__CYBERWATCH_NEG__' && !existing.eventIds.includes(event.id)) {
      existing.eventIds.push(event.id);
      await setCachedJson(key, existing, INDEX_TTL);
    }
  }
}

// ─── Corrélation ─────────────────────────────────────────────────────────────

/**
 * Trouve les événements existants qui partagent des entités avec l'événement donné.
 * @returns Map : type de corrélation → liste d'IDs d'événements corrélés
 */
async function findCorrelatedEventIds(event: UnifiedThreatEvent): Promise<{
  cveMatches: string[];
  ipMatches: string[];
  domainMatches: string[];
}> {
  const cveMatches: string[] = [];
  const ipMatches: string[] = [];
  const domainMatches: string[] = [];

  // Chercher les corrélations CVE
  for (const cve of event.extractedEntities.cves) {
    const key = `${CVE_INDEX_PREFIX}${cve}`;
    const index = await getCachedJson<EntityIndex>(key);
    if (index && index !== '__CYBERWATCH_NEG__') {
      const newIds = index.eventIds.filter((id) => id !== event.id);
      cveMatches.push(...newIds);
    }
  }

  // Chercher les corrélations IP
  for (const ip of event.extractedEntities.ips) {
    const key = `${IP_INDEX_PREFIX}${ip}`;
    const index = await getCachedJson<EntityIndex>(key);
    if (index && index !== '__CYBERWATCH_NEG__') {
      const newIds = index.eventIds.filter((id) => id !== event.id);
      ipMatches.push(...newIds);
    }
  }

  // Chercher les corrélations domaines
  for (const domain of event.extractedEntities.domains) {
    const key = `${DOMAIN_INDEX_PREFIX}${domain}`;
    const index = await getCachedJson<EntityIndex>(key);
    if (index && index !== '__CYBERWATCH_NEG__') {
      const newIds = index.eventIds.filter((id) => id !== event.id);
      domainMatches.push(...newIds);
    }
  }

  return {
    cveMatches: [...new Set(cveMatches)],
    ipMatches: [...new Set(ipMatches)],
    domainMatches: [...new Set(domainMatches)],
  };
}

/**
 * Enrichit un événement avec les corrélations croisées trouvées dans le cache.
 * Modifie l'événement en place en ajoutant :
 * - `correlatedWith` : liste des IDs d'événements corrélés
 * - `score` boost si des corrélations sont trouvées
 * - `severity` et `isUrgent` mis à jour
 *
 * @param event - L'événement à enrichir (modifié en place)
 */
export async function correlateEvent(event: UnifiedThreatEvent): Promise<void> {
  const { cveMatches, ipMatches, domainMatches } = await findCorrelatedEventIds(event);

  const allCorrelated = [...new Set([...cveMatches, ...ipMatches, ...domainMatches])];

  if (allCorrelated.length === 0) return;

  // Ajouter les corrélations
  event.correlatedWith = [
    ...(event.correlatedWith ?? []),
    ...allCorrelated,
  ].slice(0, 20); // Limiter à 20 corrélations max

  // Appliquer les boosts de score selon le type de corrélation
  if (cveMatches.length > 0) {
    event.score = applyCorrelationBoost(event.score, 'cve-match');
  }
  if (ipMatches.length > 0) {
    event.score = applyCorrelationBoost(event.score, 'ioc-match');
  }
  if (domainMatches.length > 0) {
    event.score = applyCorrelationBoost(event.score, 'domain-match');
  }

  // Recalculer la sévérité après le boost
  refreshSeverity(event);
}

/**
 * Pipeline complet pour un nouvel événement :
 * 1. Corréler avec les événements existants
 * 2. Enrichir avec EPSS, CISA KEV, MITRE ATT&CK, GreyNoise
 * 3. Indexer ses propres entités pour les corrélations futures
 *
 * @param event - L'événement à traiter (modifié en place)
 */
export async function processNewEvent(event: UnifiedThreatEvent): Promise<void> {
  // D'abord corréler avec l'existant
  await correlateEvent(event);

  // Enrichissement Phase 2 (modifier en place)
  await enrichWithEpss(event);
  await enrichWithKev(event);
  enrichWithMitre(event);
  await enrichWithGreyNoise(event);

  // Ensuite indexer pour les futurs événements
  await indexEventEntities(event);
}

// ─── Phase 2 : Enrichissements ────────────────────────────────────────────────

/**
 * Enrichit un événement avec les scores EPSS pour chaque CVE détectée.
 * Ajoute le score le plus élevé dans event.enrichments.epssScore
 * et booste le score si EPSS est significatif.
 */
async function enrichWithEpss(event: UnifiedThreatEvent): Promise<void> {
  const cves = event.extractedEntities.cves;
  if (cves.length === 0) return;

  let maxEpss = 0;
  let maxPercentile = 0;
  const epssDetails: Record<string, number> = {};

  for (const cve of cves) {
    const epssData = await getEpssScore(cve);
    if (epssData) {
      epssDetails[cve] = epssData.epss;
      if (epssData.epss > maxEpss) {
        maxEpss = epssData.epss;
        maxPercentile = epssData.percentile;
      }
    }
  }

  if (maxEpss > 0) {
    if (!event.enrichments) event.enrichments = {};
    event.enrichments['epssScore'] = maxEpss;
    event.enrichments['epssPercentile'] = maxPercentile;
    if (Object.keys(epssDetails).length > 1) {
      event.enrichments['epssDetails'] = epssDetails;
    }

    // Boost scoring
    if (maxEpss >= 0.8) {
      event.score = Math.min(100, event.score + 25);
    } else if (maxEpss >= 0.5) {
      event.score = Math.min(100, event.score + 15);
    } else if (maxEpss >= 0.2) {
      event.score = Math.min(100, event.score + 8);
    }

    refreshSeverity(event);
  }
}

/**
 * Enrichit un événement avec le statut CISA KEV (Known Exploited Vulnerability).
 */
async function enrichWithKev(event: UnifiedThreatEvent): Promise<void> {
  const cves = event.extractedEntities.cves;
  if (cves.length === 0) return;

  for (const cve of cves) {
    const exploited = await isKnownExploited(cve);
    if (exploited) {
      if (!event.enrichments) event.enrichments = {};
      event.enrichments['knownExploited'] = true;
      event.enrichments['kevCve'] = cve;

      // Boost significatif pour les KEV
      event.score = Math.min(100, event.score + 20);
      refreshSeverity(event);
      break; // Un seul suffit
    }
  }
}

/**
 * Enrichit un événement avec les TTPs MITRE ATT&CK.
 * Mappe les malwareNames et toolNames vers des techniques connues.
 */
function enrichWithMitre(event: UnifiedThreatEvent): void {
  if (!isMitreLoaded()) return;

  const { malwareNames, attackTypes } = event.extractedEntities;
  if (malwareNames.length === 0 && attackTypes.length === 0) return;

  const ttps = lookupTTPs(malwareNames, []);
  if (ttps.length > 0) {
    if (!event.enrichments) event.enrichments = {};
    event.enrichments['mitreTTPs'] = ttps;

    // Ajouter les TTP IDs aux attackTypes
    const ttpIds = ttps.map(t => t.split(' — ')[0]).filter((t): t is string => !!t);
    event.extractedEntities.attackTypes = [
      ...new Set([...event.extractedEntities.attackTypes, ...ttpIds]),
    ];
  }
}

/**
 * Enrichit les IOCs avec la classification GreyNoise.
 * Démotion pour les IPs bénignes, boost pour les malveillantes.
 */
async function enrichWithGreyNoise(event: UnifiedThreatEvent): Promise<void> {
  const ips = event.extractedEntities.ips;
  if (ips.length === 0) return;

  // Vérifier seulement la première IP (pour limiter les appels cache)
  const ip = ips[0];
  if (!ip) return;

  const gnData = await getGreyNoiseClassification(ip);
  if (!gnData) return;

  if (!event.enrichments) event.enrichments = {};
  event.enrichments['greynoiseClassification'] = gnData.classification;
  event.enrichments['greynoiseName'] = gnData.name;
  event.enrichments['greynoiseRiot'] = gnData.riot;

  if (gnData.classification === 'benign') {
    event.score = Math.max(0, event.score - 20);
    refreshSeverity(event);
  } else if (gnData.classification === 'malicious') {
    event.score = Math.min(100, event.score + 10);
    refreshSeverity(event);
  }
}


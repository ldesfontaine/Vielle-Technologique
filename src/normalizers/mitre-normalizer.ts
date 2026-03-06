/**
 * Normalizer/Lookup pour MITRE ATT&CK Enterprise.
 * Charge le bundle STIX JSON depuis GitHub et construit des index en mémoire :
 * - malware name → techniques associées
 * - tool name → techniques associées
 * - technique ID → nom + tactiques
 *
 * N'est pas un producteur d'événements mais un enrichisseur : expose lookupTTPs()
 * qui est appelé par le cross-correlator pour enrichir extractedEntities.attackTypes.
 */

// ─── Types STIX simplifiés ───────────────────────────────────────────────────

interface StixObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  external_references?: Array<{
    source_name?: string;
    external_id?: string;
    url?: string;
  }>;
  kill_chain_phases?: Array<{
    kill_chain_name?: string;
    phase_name?: string;
  }>;
  // relationship fields
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
  // revoked/deprecated
  revoked?: boolean;
  'x_mitre_deprecated'?: boolean;
}

interface StixBundle {
  type: string;
  id: string;
  objects: StixObject[];
}

// ─── Types internes ──────────────────────────────────────────────────────────

interface TechniqueInfo {
  id: string;        // ex: "T1059"
  name: string;      // ex: "Command and Scripting Interpreter"
  tactics: string[]; // ex: ["execution"]
}

// ─── Cache mémoire ───────────────────────────────────────────────────────────

/** Index : nom de malware (lowercase) → technique IDs */
const malwareToTechniques = new Map<string, string[]>();
/** Index : nom de tool (lowercase) → technique IDs */
const toolToTechniques = new Map<string, string[]>();
/** Index : technique ID (ex: "T1059") → TechniqueInfo */
const techniqueIndex = new Map<string, TechniqueInfo>();
/** Index : STIX ID → ATT&CK technique ID */
const stixIdToTechniqueId = new Map<string, string>();
/** Index : STIX ID → nom (pour résolution des relations) */
const stixIdToName = new Map<string, string>();

let isLoaded = false;
let lastLoadTime = 0;

// ─── Chargement du bundle ────────────────────────────────────────────────────

/**
 * Charge et indexe le bundle STIX ATT&CK Enterprise.
 * Appelé 1x par semaine par le poll loop.
 * @param bundle - Le JSON STIX parsé
 */
export function loadAttackBundle(bundle: StixBundle): void {
  const objects = bundle.objects ?? [];

  // Reset des index
  malwareToTechniques.clear();
  toolToTechniques.clear();
  techniqueIndex.clear();
  stixIdToTechniqueId.clear();
  stixIdToName.clear();

  // Phase 1 : indexer les techniques (attack-pattern)
  for (const obj of objects) {
    if (obj.revoked || obj['x_mitre_deprecated']) continue;

    if (obj.type === 'attack-pattern') {
      const attackId = obj.external_references?.find(
        r => r.source_name === 'mitre-attack'
      )?.external_id;

      if (attackId) {
        const tactics = (obj.kill_chain_phases ?? [])
          .filter(p => p.kill_chain_name === 'mitre-attack')
          .map(p => p.phase_name ?? '');

        techniqueIndex.set(attackId, {
          id: attackId,
          name: obj.name ?? attackId,
          tactics,
        });

        stixIdToTechniqueId.set(obj.id, attackId);
      }
    }

    // Enregistrer les noms pour résolution
    if (obj.name) {
      stixIdToName.set(obj.id, obj.name.toLowerCase());
    }
  }

  // Phase 2 : indexer les relations (malware/tool → technique)
  for (const obj of objects) {
    if (obj.type !== 'relationship') continue;
    if (obj.relationship_type !== 'uses') continue;
    if (obj.revoked) continue;

    const sourceName = stixIdToName.get(obj.source_ref ?? '');
    const targetTechId = stixIdToTechniqueId.get(obj.target_ref ?? '');

    if (!sourceName || !targetTechId) continue;

    // Déterminer si la source est un malware ou un tool
    const sourceRef = obj.source_ref ?? '';
    if (sourceRef.startsWith('malware--')) {
      const existing = malwareToTechniques.get(sourceName) ?? [];
      if (!existing.includes(targetTechId)) {
        existing.push(targetTechId);
        malwareToTechniques.set(sourceName, existing);
      }
    } else if (sourceRef.startsWith('tool--')) {
      const existing = toolToTechniques.get(sourceName) ?? [];
      if (!existing.includes(targetTechId)) {
        existing.push(targetTechId);
        toolToTechniques.set(sourceName, existing);
      }
    }
  }

  isLoaded = true;
  lastLoadTime = Date.now();

  console.info(
    `[mitre] ATT&CK chargé : ${techniqueIndex.size} techniques, ` +
    `${malwareToTechniques.size} malwares, ${toolToTechniques.size} tools indexés`
  );
}

// ─── API de lookup ───────────────────────────────────────────────────────────

/**
 * Vérifie si le bundle ATT&CK est chargé en mémoire.
 */
export function isMitreLoaded(): boolean {
  return isLoaded;
}

/**
 * Retourne le timestamp du dernier chargement.
 */
export function getMitreLastLoadTime(): number {
  return lastLoadTime;
}

/**
 * Recherche les TTPs (Techniques, Tactics, Procedures) associées à un ensemble
 * de noms de malwares et types d'attaques.
 *
 * @param malwareNames - Noms de malwares détectés (ex: ["lockbit", "emotet"])
 * @param toolNames - Noms d'outils détectés (ex: ["cobalt strike"])
 * @returns Tableau de strings "T1234 — Nom de technique (tactic1, tactic2)"
 */
export function lookupTTPs(
  malwareNames: string[],
  toolNames: string[] = []
): string[] {
  if (!isLoaded) return [];

  const techniqueIds = new Set<string>();

  // Chercher les techniques des malwares
  for (const name of malwareNames) {
    const lower = name.toLowerCase();
    const techniques = malwareToTechniques.get(lower);
    if (techniques) {
      for (const t of techniques) techniqueIds.add(t);
    }
  }

  // Chercher les techniques des tools
  for (const name of toolNames) {
    const lower = name.toLowerCase();
    const techniques = toolToTechniques.get(lower);
    if (techniques) {
      for (const t of techniques) techniqueIds.add(t);
    }
  }

  // Construire les labels lisibles
  const results: string[] = [];
  for (const techId of techniqueIds) {
    const info = techniqueIndex.get(techId);
    if (info) {
      const tactics = info.tactics.length > 0
        ? ` (${info.tactics.join(', ')})`
        : '';
      results.push(`${info.id} — ${info.name}${tactics}`);
    }
  }

  return results.slice(0, 20); // Limiter à 20 TTPs max
}

/**
 * Recherche simple : un nom de malware a-t-il des TTPs connues ?
 */
export function hasTTPs(malwareName: string): boolean {
  if (!isLoaded) return false;
  return malwareToTechniques.has(malwareName.toLowerCase());
}

/**
 * Retourne les statistiques du cache MITRE en mémoire.
 */
export function getMitreStats(): {
  loaded: boolean;
  techniques: number;
  malwares: number;
  tools: number;
  lastLoadTime: number;
} {
  return {
    loaded: isLoaded,
    techniques: techniqueIndex.size,
    malwares: malwareToTechniques.size,
    tools: toolToTechniques.size,
    lastLoadTime,
  };
}

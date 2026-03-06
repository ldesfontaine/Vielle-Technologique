/**
 * Classificateur par mots-clés de cybersécurité.
 * Attribue des catégories d'attaque et des poids de scoring aux événements
 * en fonction des mots-clés détectés dans le titre et la description.
 * Supporte les mots-clés en anglais ET en français.
 */

export interface KeywordMatch {
  /** Catégorie d'attaque identifiée */
  category: string;
  /** Mots-clés correspondants trouvés dans le texte */
  matchedKeywords: string[];
  /** Poids total de scoring pour cette catégorie */
  scoreWeight: number;
}

export interface ClassificationResult {
  /** Types d'attaques détectés */
  attackTypes: string[];
  /** Noms de malwares identifiés */
  malwareNames: string[];
  /** Score bonus total des mots-clés */
  totalKeywordScore: number;
  /** Détail des correspondances par catégorie */
  matches: KeywordMatch[];
}

/** Définition d'une catégorie de mots-clés */
interface KeywordCategory {
  name: string;
  weight: number;
  keywords: string[];
}

// ─── Dictionnaire de mots-clés ────────────────────────────────────────────────

const KEYWORD_CATEGORIES: KeywordCategory[] = [
  {
    name: 'zero-day',
    weight: 30,
    keywords: [
      'zero-day', 'zero day', '0day', '0-day',
      'jour zéro', 'zéro-day', 'zéro jour',
      'actively exploited', 'exploité activement',
      'in the wild', 'dans la nature', 'exploitation active',
      'wild exploitation',
    ],
  },
  {
    name: 'ransomware',
    weight: 25,
    keywords: [
      'ransomware', 'ransom', 'rançongiciel', 'rançon',
      'lockbit', 'blackcat', 'alphv', 'clop', 'cl0p',
      'conti', 'hive', 'revil', 'ryuk', 'maze', 'darkside',
      'blackbyte', 'royal', 'akira', 'play', 'noname',
      'medusa', 'rhysida', 'hunters', 'dispossessor',
    ],
  },
  {
    name: 'actively-exploited',
    weight: 30,
    keywords: [
      'actively exploited', 'active exploitation', 'known exploited',
      'exploited in the wild', 'under active attack',
      'exploité activement', 'exploitation active', 'exploité en conditions réelles',
      'kev', 'known exploited vulnerability',
    ],
  },
  {
    name: 'critical-severity',
    weight: 20,
    keywords: [
      'critical', 'critique', 'cvss 9', 'cvss 10',
      'cvss3 9', 'cvss3 10', 'cvssv3 9', 'cvssv3 10',
      'severity critical', 'sévérité critique',
      'remote code execution', 'rce', 'exécution de code',
      'unauthenticated', 'non authentifié', 'pre-auth',
    ],
  },
  {
    name: 'phishing',
    weight: 15,
    keywords: [
      'phishing', 'hameçonnage', 'spear phishing', 'spearphishing',
      'whaling', 'vishing', 'smishing', 'credential harvesting',
      'vol d\'identifiants', 'faux site',
    ],
  },
  {
    name: 'apt',
    weight: 20,
    keywords: [
      'apt', 'advanced persistent threat', 'menace persistante avancée',
      'nation-state', 'state-sponsored', 'parrainé par un état',
      'cozy bear', 'fancy bear', 'lazarus', 'equation group',
      'volt typhoon', 'salt typhoon', 'midnight blizzard',
      'sandworm', 'turla', 'kimsuky', 'charming kitten',
    ],
  },
  {
    name: 'ddos',
    weight: 10,
    keywords: [
      'ddos', 'denial of service', 'déni de service',
      'distributed denial', 'botnet', 'flood attack',
      'amplification', 'reflection attack',
    ],
  },
  {
    name: 'data-breach',
    weight: 20,
    keywords: [
      'data breach', 'fuite de données', 'violation de données',
      'data leak', 'données exposées', 'exposed database',
      'stolen data', 'données volées', 'compromised records',
      'millions of records', 'millions d\'enregistrements',
    ],
  },
  {
    name: 'supply-chain',
    weight: 25,
    keywords: [
      'supply chain', 'chaîne d\'approvisionnement', 'chaîne logistique',
      'software supply chain', 'dependency confusion', 'typosquatting',
      'malicious package', 'paquet malveillant', 'solarwinds',
      'xz utils', 'backdoor package',
    ],
  },
  {
    name: 'patch-available',
    weight: 15,
    keywords: [
      'patch', 'update available', 'mise à jour disponible',
      'patch tuesday', 'security update', 'correctif',
      'hotfix', 'fix available', 'corrective patch',
    ],
  },
  {
    name: 'proof-of-concept',
    weight: 20,
    keywords: [
      'proof of concept', 'poc', 'preuve de concept',
      'exploit code', 'exploit publié', 'exploit released',
      'public exploit', 'working exploit',
    ],
  },
];

// ─── Noms de malwares connus ──────────────────────────────────────────────────

const KNOWN_MALWARE_NAMES: string[] = [
  // Ransomwares
  'lockbit', 'blackcat', 'alphv', 'clop', 'cl0p', 'conti', 'hive', 'revil',
  'ryuk', 'maze', 'darkside', 'blackbyte', 'royal', 'akira', 'play', 'medusa',
  'rhysida', 'hunters international', 'dispossessor', 'fog', 'lynx',
  // Trojans/RATs
  'emotet', 'qakbot', 'qbot', 'icedid', 'bumblebee', 'pikabot', 'gootloader',
  'dridex', 'trickbot', 'bazarloader', 'cobalt strike', 'metasploit',
  // Stealers
  'redline', 'raccoon', 'vidar', 'lumma', 'aurora', 'cryptbot',
  // Bootkits/Rootkits
  'blacklotus', 'uefi', 'rootkit',
  // Backdoors
  'solarwinds', 'sunburst', 'notpetya', 'wannacry', 'petya',
  // Botnets
  'mirai', 'qakbot', 'necurs',
];

// ─── Démotions (bruit) ────────────────────────────────────────────────────────

const NOISE_KEYWORDS: { keywords: string[]; penalty: number }[] = [
  {
    keywords: ['opinion', 'editorial', 'review', 'analysis', 'podcast', 'interview', 'avis', 'chronique'],
    penalty: -15,
  },
  {
    keywords: ['rumor', 'rumour', 'unconfirmed', 'allegedly', 'reportedly', 'rumeur', 'non confirmé', 'selon certains'],
    penalty: -10,
  },
  {
    keywords: ['weekly roundup', 'monthly summary', 'newsletter', 'digest', 'résumé hebdomadaire', 'bilan mensuel'],
    penalty: -10,
  },
];

// ─── Logique principale ───────────────────────────────────────────────────────

/**
 * Classifie un texte selon les catégories de menaces cybersécurité.
 * @param text - Texte combiné (titre + description) à analyser
 * @returns Résultat de classification avec types d'attaques et score
 */
export function classifyKeywords(text: string): ClassificationResult {
  const lowerText = text.toLowerCase();
  const attackTypes: string[] = [];
  const matches: KeywordMatch[] = [];
  let totalKeywordScore = 0;

  // Analyser chaque catégorie de mots-clés
  for (const category of KEYWORD_CATEGORIES) {
    const matchedKeywords = category.keywords.filter((kw) =>
      lowerText.includes(kw.toLowerCase())
    );

    if (matchedKeywords.length > 0) {
      attackTypes.push(category.name);
      matches.push({
        category: category.name,
        matchedKeywords,
        scoreWeight: category.weight,
      });
      totalKeywordScore += category.weight;
    }
  }

  // Appliquer les pénalités de bruit
  for (const noiseGroup of NOISE_KEYWORDS) {
    const hasNoise = noiseGroup.keywords.some((kw) =>
      lowerText.includes(kw.toLowerCase())
    );
    if (hasNoise) {
      totalKeywordScore += noiseGroup.penalty;
    }
  }

  // Extraire les noms de malwares
  const malwareNames = KNOWN_MALWARE_NAMES.filter((name) =>
    lowerText.includes(name.toLowerCase())
  );

  return {
    attackTypes: [...new Set(attackTypes)],
    malwareNames: [...new Set(malwareNames)],
    totalKeywordScore,
    matches,
  };
}

/**
 * Calcule la pénalité de bruit d'un texte.
 * Utilisé pour démoter les articles non pertinents.
 */
export function calculateNoisePenalty(text: string): number {
  const lowerText = text.toLowerCase();
  let penalty = 0;
  for (const noiseGroup of NOISE_KEYWORDS) {
    const hasNoise = noiseGroup.keywords.some((kw) =>
      lowerText.includes(kw.toLowerCase())
    );
    if (hasNoise) {
      penalty += noiseGroup.penalty;
    }
  }
  return penalty;
}

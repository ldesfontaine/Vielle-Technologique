/**
 * Extracteur d'IOCs (Indicators of Compromise).
 * Extrait IPs, domaines et hashes de fichiers depuis du texte libre.
 * Les IPs privées/réservées et les domaines légitimes sont filtrés.
 */

// ─── Regex ──────────────────────────────────────────────────────────────────

/** IPv4 publique */
const IPV4_REGEX =
  /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g;

/** Nom de domaine (sous-domaines inclus, TLD 2-6 chars) */
const DOMAIN_REGEX =
  /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6})\b/gi;

/** MD5 : 32 caractères hexadécimaux */
const MD5_REGEX = /\b([0-9a-fA-F]{32})\b/g;

/** SHA1 : 40 caractères hexadécimaux */
const SHA1_REGEX = /\b([0-9a-fA-F]{40})\b/g;

/** SHA256 : 64 caractères hexadécimaux */
const SHA256_REGEX = /\b([0-9a-fA-F]{64})\b/g;

// ─── Listes de filtrage ──────────────────────────────────────────────────────

/**
 * Plages d'IPs privées/réservées à exclure.
 * Ces IPs ne sont pas des IOCs valides car non routables sur internet.
 */
const PRIVATE_IP_RANGES: [number, number][] = [
  [ipToInt('0.0.0.0'), ipToInt('0.255.255.255')],       // Réseau actuel
  [ipToInt('10.0.0.0'), ipToInt('10.255.255.255')],      // Privé classe A
  [ipToInt('100.64.0.0'), ipToInt('100.127.255.255')],   // Shared address space
  [ipToInt('127.0.0.0'), ipToInt('127.255.255.255')],    // Loopback
  [ipToInt('169.254.0.0'), ipToInt('169.254.255.255')],  // Link-local
  [ipToInt('172.16.0.0'), ipToInt('172.31.255.255')],    // Privé classe B
  [ipToInt('192.0.0.0'), ipToInt('192.0.0.255')],        // IETF Protocol
  [ipToInt('192.0.2.0'), ipToInt('192.0.2.255')],        // Documentation
  [ipToInt('192.168.0.0'), ipToInt('192.168.255.255')],  // Privé classe C
  [ipToInt('198.18.0.0'), ipToInt('198.19.255.255')],    // Benchmark
  [ipToInt('198.51.100.0'), ipToInt('198.51.100.255')],  // Documentation
  [ipToInt('203.0.113.0'), ipToInt('203.0.113.255')],    // Documentation
  [ipToInt('224.0.0.0'), ipToInt('239.255.255.255')],    // Multicast
  [ipToInt('240.0.0.0'), ipToInt('255.255.255.255')],    // Réservé/Broadcast
];

/**
 * Domaines légitimes à exclure pour réduire les faux positifs.
 * Ces domaines apparaissent souvent dans les articles mais ne sont pas des IOCs.
 */
const LEGITIMATE_DOMAINS = new Set([
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
  'twitter.com', 'github.com', 'youtube.com', 'linkedin.com', 'wikipedia.org',
  'cloudflare.com', 'amazonaws.com', 'azure.com', 'office.com', 'windows.com',
  'adobe.com', 'mozilla.org', 'firefox.com', 'chrome.com', 'safari.com',
  'npmjs.com', 'pypi.org', 'crates.io', 'golang.org', 'rust-lang.org',
  'cve.mitre.org', 'nvd.nist.gov', 'cisa.gov', 'cert.ssi.gouv.fr',
  'bleepingcomputer.com', 'krebsonsecurity.com', 'securityweek.com',
  'theregister.com', 'wired.com', 'arstechnica.com', 'techcrunch.com',
  'example.com', 'example.org', 'localhost',
]);

// ─── Fonctions utilitaires ───────────────────────────────────────────────────

/** Convertit une adresse IPv4 en entier 32 bits */
function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) | parseInt(octet, 10), 0) >>> 0;
}

/** Vérifie si une IP est privée/réservée */
function isPrivateIp(ip: string): boolean {
  const intIp = ipToInt(ip);
  return PRIVATE_IP_RANGES.some(([start, end]) => intIp >= start && intIp <= end);
}

/**
 * Vérifie si un domaine est probablement légitime (à exclure).
 * Vérifie aussi les sous-domaines des domaines légitimes connus.
 */
function isLegitimateDomain(domain: string): boolean {
  const lower = domain.toLowerCase();
  if (LEGITIMATE_DOMAINS.has(lower)) return true;
  // Vérifier si c'est un sous-domaine d'un domaine légitime
  for (const legit of LEGITIMATE_DOMAINS) {
    if (lower.endsWith(`.${legit}`)) return true;
  }
  return false;
}

// ─── Exports principaux ──────────────────────────────────────────────────────

/**
 * Extrait les adresses IP publiques uniques d'un texte.
 * Filtre les IPs privées, loopback et réservées.
 */
export function extractIps(text: string): string[] {
  const matches = text.match(IPV4_REGEX);
  if (!matches) return [];

  const unique = new Set(
    matches.filter((ip) => !isPrivateIp(ip))
  );
  return Array.from(unique).sort();
}

/**
 * Extrait les noms de domaine potentiellement malveillants d'un texte.
 * Filtre les domaines légitimes connus pour réduire les faux positifs.
 */
export function extractDomains(text: string): string[] {
  const matches = text.match(DOMAIN_REGEX);
  if (!matches) return [];

  const unique = new Set(
    matches
      .map((d) => d.toLowerCase())
      .filter((d) => !isLegitimateDomain(d))
      // Exclure les domaines trop courts (probablement des artefacts)
      .filter((d) => d.split('.').every((part) => part.length > 0) && d.length > 5)
  );
  return Array.from(unique).sort();
}

/**
 * Extrait les hashes de fichiers (MD5, SHA1, SHA256) d'un texte.
 * Les hashes sont normalisés en minuscules.
 */
export function extractHashes(text: string): string[] {
  const hashes = new Set<string>();

  // SHA256 en premier pour éviter les sous-matches avec MD5/SHA1
  const sha256Matches = text.match(SHA256_REGEX);
  if (sha256Matches) {
    sha256Matches.forEach((h) => hashes.add(h.toLowerCase()));
  }

  // Retirer les SHA256 du texte avant de chercher SHA1/MD5
  const textWithoutSha256 = text.replace(SHA256_REGEX, '');

  const sha1Matches = textWithoutSha256.match(SHA1_REGEX);
  if (sha1Matches) {
    sha1Matches.forEach((h) => hashes.add(h.toLowerCase()));
  }

  const textWithoutSha1 = textWithoutSha256.replace(SHA1_REGEX, '');
  const md5Matches = textWithoutSha1.match(MD5_REGEX);
  if (md5Matches) {
    md5Matches.forEach((h) => hashes.add(h.toLowerCase()));
  }

  return Array.from(hashes).sort();
}

/**
 * Extrait tous les IOCs d'un texte en une seule passe.
 */
export function extractAllIocs(text: string): {
  ips: string[];
  domains: string[];
  hashes: string[];
} {
  return {
    ips: extractIps(text),
    domains: extractDomains(text),
    hashes: extractHashes(text),
  };
}

/**
 * Configuration des feeds RSS par tier de crédibilité.
 * Les feeds sont organisés en 4 niveaux :
 *   Tier 1 : Sources officielles gouvernementales/institutionnelles
 *   Tier 2 : Médias cybersécurité reconnus
 *   Tier 3 : Blogs experts et recherche
 *   Tier 4 : Communautés et agrégateurs
 */

export interface FeedConfig {
  /** Identifiant unique du feed */
  id: string;
  /** Nom affiché de la source */
  name: string;
  /** URL du feed RSS/Atom */
  url: string;
  /** Tier de crédibilité (1-4) */
  tier: 1 | 2 | 3 | 4;
  /** Catégorie métier */
  category: 'advisory' | 'news' | 'vulnerability' | 'threat-intel' | 'ransomware';
  /** Intervalle de polling en secondes */
  intervalSeconds: number;
  /** Langue principale du feed */
  lang: 'fr' | 'en';
}

export const RSS_FEEDS: FeedConfig[] = [
  // ─── Tier 1 : Sources officielles ───────────────────────────────────────────
  {
    id: 'cert-fr',
    name: 'CERT-FR',
    url: 'https://www.cert.ssi.gouv.fr/feed/',
    tier: 1,
    category: 'advisory',
    intervalSeconds: 900,
    lang: 'fr',
  },
  {
    id: 'cisa-advisories',
    name: 'CISA Advisories',
    url: 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    tier: 1,
    category: 'advisory',
    intervalSeconds: 900,
    lang: 'en',
  },
  {
    id: 'cisa-kevs',
    name: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/uscert/ncas/current-activity.xml',
    tier: 1,
    category: 'vulnerability',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'nvd-cve',
    name: 'NVD CVE Recent',
    url: 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml',
    tier: 1,
    category: 'vulnerability',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'anssi-publications',
    name: 'ANSSI Publications',
    url: 'https://www.ssi.gouv.fr/flux-rss/actualite/rss.xml',
    tier: 1,
    category: 'advisory',
    intervalSeconds: 3600,
    lang: 'fr',
  },
  {
    id: 'microsoft-msrc',
    name: 'Microsoft Security Response Center',
    url: 'https://api.msrc.microsoft.com/update-guide/rss',
    tier: 1,
    category: 'vulnerability',
    intervalSeconds: 3600,
    lang: 'en',
  },

  // ─── Tier 2 : Médias spécialisés reconnus ───────────────────────────────────
  {
    id: 'bleepingcomputer',
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    tier: 2,
    category: 'news',
    intervalSeconds: 600,
    lang: 'en',
  },
  {
    id: 'krebs-on-security',
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    tier: 2,
    category: 'news',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'the-hacker-news',
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    tier: 2,
    category: 'news',
    intervalSeconds: 600,
    lang: 'en',
  },
  {
    id: 'dark-reading',
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss.xml',
    tier: 2,
    category: 'news',
    intervalSeconds: 900,
    lang: 'en',
  },
  {
    id: 'securityweek',
    name: 'SecurityWeek',
    url: 'https://feeds.feedburner.com/securityweek',
    tier: 2,
    category: 'news',
    intervalSeconds: 900,
    lang: 'en',
  },
  {
    id: 'threatpost',
    name: 'Threatpost',
    url: 'https://threatpost.com/feed/',
    tier: 2,
    category: 'news',
    intervalSeconds: 900,
    lang: 'en',
  },
  {
    id: 'cyberscoop',
    name: 'CyberScoop',
    url: 'https://cyberscoop.com/feed/',
    tier: 2,
    category: 'news',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'zdnet-security',
    name: 'ZDNet Security',
    url: 'https://www.zdnet.com/topic/security/rss.xml',
    tier: 2,
    category: 'news',
    intervalSeconds: 1800,
    lang: 'en',
  },

  // ─── Tier 3 : Blogs experts et recherche ────────────────────────────────────
  {
    id: 'schneier-security',
    name: 'Schneier on Security',
    url: 'https://www.schneier.com/feed/atom/',
    tier: 3,
    category: 'news',
    intervalSeconds: 3600,
    lang: 'en',
  },
  {
    id: 'cisco-talos',
    name: 'Cisco Talos Intelligence',
    url: 'https://blog.talosintelligence.com/feeds/posts/default',
    tier: 3,
    category: 'threat-intel',
    intervalSeconds: 3600,
    lang: 'en',
  },
  {
    id: 'crowdstrike-blog',
    name: 'CrowdStrike Blog',
    url: 'https://www.crowdstrike.com/blog/feed/',
    tier: 3,
    category: 'threat-intel',
    intervalSeconds: 3600,
    lang: 'en',
  },
  {
    id: 'mandiant-blog',
    name: 'Mandiant Blog',
    url: 'https://www.mandiant.com/resources/blog/rss.xml',
    tier: 3,
    category: 'threat-intel',
    intervalSeconds: 7200,
    lang: 'en',
  },
  {
    id: 'recorded-future',
    name: 'Recorded Future',
    url: 'https://www.recordedfuture.com/feed',
    tier: 3,
    category: 'threat-intel',
    intervalSeconds: 7200,
    lang: 'en',
  },
  {
    id: 'sekoia-blog',
    name: 'Sekoia Blog',
    url: 'https://blog.sekoia.io/feed/',
    tier: 3,
    category: 'threat-intel',
    intervalSeconds: 7200,
    lang: 'fr',
  },
  {
    id: 'sans-isc',
    name: 'SANS Internet Storm Center',
    url: 'https://isc.sans.edu/rssfeed_full.xml',
    tier: 3,
    category: 'threat-intel',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'troyhunt',
    name: 'Troy Hunt',
    url: 'https://www.troyhunt.com/rss/',
    tier: 3,
    category: 'news',
    intervalSeconds: 7200,
    lang: 'en',
  },
  {
    id: 'google-project-zero',
    name: 'Google Project Zero',
    url: 'https://googleprojectzero.blogspot.com/feeds/posts/default',
    tier: 3,
    category: 'vulnerability',
    intervalSeconds: 86400,
    lang: 'en',
  },
  {
    id: 'github-security',
    name: 'GitHub Security Blog',
    url: 'https://github.blog/category/security/feed/',
    tier: 3,
    category: 'vulnerability',
    intervalSeconds: 7200,
    lang: 'en',
  },

  // ─── Tier 4 : Communautés et agrégateurs ────────────────────────────────────
  {
    id: 'reddit-netsec',
    name: 'Reddit /r/netsec',
    url: 'https://www.reddit.com/r/netsec/.rss',
    tier: 4,
    category: 'news',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'reddit-cybersecurity',
    name: 'Reddit /r/cybersecurity',
    url: 'https://www.reddit.com/r/cybersecurity/.rss',
    tier: 4,
    category: 'news',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'hackernews-security',
    name: 'Hacker News (Security)',
    url: 'https://hnrss.org/newest?q=security+vulnerability+CVE',
    tier: 4,
    category: 'news',
    intervalSeconds: 3600,
    lang: 'en',
  },
  {
    id: 'cert-eu',
    name: 'CERT-EU',
    url: 'https://www.cert.europa.eu/publications/rss',
    tier: 1,
    category: 'advisory',
    intervalSeconds: 3600,
    lang: 'en',
  },
  {
    id: 'ncsc-uk',
    name: 'NCSC UK',
    url: 'https://www.ncsc.gov.uk/api/1/services/v1/feed.atom',
    tier: 1,
    category: 'advisory',
    intervalSeconds: 3600,
    lang: 'en',
  },
  {
    id: 'exploit-db',
    name: 'Exploit-DB',
    url: 'https://www.exploit-db.com/rss.xml',
    tier: 3,
    category: 'vulnerability',
    intervalSeconds: 1800,
    lang: 'en',
  },
  {
    id: 'packet-storm',
    name: 'Packet Storm Security',
    url: 'https://packetstormsecurity.com/headlines.xml',
    tier: 3,
    category: 'vulnerability',
    intervalSeconds: 1800,
    lang: 'en',
  },
];

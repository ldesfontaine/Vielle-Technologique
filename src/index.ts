/**
 * Point d'entrée principal du moteur de veille cybersécurité.
 *
 * Fournit une API HTTP minimale pour consulter les événements collectés :
 * - GET /api/feed          → Tous les événements récents triés par score
 * - GET /api/feed?type=X   → Filtrer par type (NEWS, VULNERABILITY, IOC, etc.)
 * - GET /api/feed?severity=X → Filtrer par sévérité
 * - GET /api/threats       → IOCs actifs uniquement
 * - GET /api/cve/:id       → Détail d'une CVE avec corrélations
 * - GET /api/stats         → Statistiques globales
 * - GET /api/health        → Santé du système
 */

import * as http from 'http';
import { startPollLoop, getEventBuffer } from './poll-loop.js';
import { ThreatEventType, SeverityLevel } from './models/unified-event.js';
import { getMemoryCacheStats } from './cache/redis.js';
import { getCircuitBreakersStatus } from './fetchers/rss-fetcher.js';

// ─── Configuration ────────────────────────────────────────────────────────────

const PORT = parseInt(process.env['PORT'] ?? '3000', 10);

// ─── Utilitaires HTTP ─────────────────────────────────────────────────────────

/** Envoie une réponse JSON */
function sendJson(res: http.ServerResponse, statusCode: number, data: unknown): void {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
}

/** Parse les query params d'une URL */
function parseQuery(url: string): Record<string, string> {
  const params: Record<string, string> = {};
  const questionMark = url.indexOf('?');
  if (questionMark === -1) return params;

  const queryString = url.slice(questionMark + 1);
  for (const pair of queryString.split('&')) {
    const [key, value] = pair.split('=');
    if (key) params[decodeURIComponent(key)] = decodeURIComponent(value ?? '');
  }
  return params;
}

// ─── Handlers d'API ───────────────────────────────────────────────────────────

/** GET /api/feed — Tous les événements récents, filtrables et triés par score */
function handleFeed(
  _req: http.IncomingMessage,
  res: http.ServerResponse,
  query: Record<string, string>
): void {
  let events = getEventBuffer();

  // Filtrage par type
  if (query['type']) {
    const type = query['type'].toUpperCase() as ThreatEventType;
    events = events.filter((e) => e.type === type);
  }

  // Filtrage par sévérité
  if (query['severity']) {
    const severity = query['severity'].toLowerCase() as SeverityLevel;
    events = events.filter((e) => e.severity === severity);
  }

  // Filtrage par source
  if (query['source']) {
    const source = query['source'].toLowerCase();
    events = events.filter((e) => e.source.toLowerCase().includes(source));
  }

  // Tri par score décroissant
  events.sort((a, b) => b.score - a.score);

  // Pagination
  const limit = Math.min(parseInt(query['limit'] ?? '50', 10), 200);
  const offset = parseInt(query['offset'] ?? '0', 10);
  const paginated = events.slice(offset, offset + limit);

  sendJson(res, 200, {
    total: events.length,
    limit,
    offset,
    events: paginated,
  });
}

/** GET /api/threats — IOCs actifs uniquement */
function handleThreats(res: http.ServerResponse): void {
  const events = getEventBuffer()
    .filter((e) => e.type === 'IOC')
    .sort((a, b) => b.score - a.score)
    .slice(0, 100);

  sendJson(res, 200, { count: events.length, threats: events });
}

/** GET /api/cve/:id — Détail d'une CVE avec ses corrélations */
function handleCve(res: http.ServerResponse, cveId: string): void {
  const upperCve = cveId.toUpperCase();
  const events = getEventBuffer().filter((e) =>
    e.extractedEntities.cves.includes(upperCve)
  );

  if (events.length === 0) {
    sendJson(res, 404, { error: `CVE ${upperCve} non trouvée`, cve: upperCve });
    return;
  }

  sendJson(res, 200, {
    cve: upperCve,
    eventCount: events.length,
    events: events.sort((a, b) => b.score - a.score),
  });
}

/** GET /api/stats — Statistiques globales */
function handleStats(res: http.ServerResponse): void {
  const events = getEventBuffer();

  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const bySource: Record<string, number> = {};

  for (const event of events) {
    byType[event.type] = (byType[event.type] ?? 0) + 1;
    bySeverity[event.severity] = (bySeverity[event.severity] ?? 0) + 1;
    bySource[event.source] = (bySource[event.source] ?? 0) + 1;
  }

  const urgentCount = events.filter((e) => e.isUrgent).length;
  const avgScore =
    events.length > 0
      ? Math.round(events.reduce((sum, e) => sum + e.score, 0) / events.length)
      : 0;

  sendJson(res, 200, {
    totalEvents: events.length,
    urgentEvents: urgentCount,
    averageScore: avgScore,
    byType,
    bySeverity,
    bySource: Object.fromEntries(
      Object.entries(bySource)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 20)
    ),
  });
}

/** GET /api/health — Santé du système */
function handleHealth(res: http.ServerResponse): void {
  const events = getEventBuffer();
  const memCache = getMemoryCacheStats();
  const circuitBreakers = getCircuitBreakersStatus();

  const openCircuits = Object.entries(circuitBreakers)
    .filter(([, state]) => state.isOpen)
    .map(([id]) => id);

  const newestEvent = events.length > 0 ? Math.max(...events.map((e) => e.timestamp)) : null;
  const dataAgeSeconds = newestEvent
    ? Math.round((Date.now() - newestEvent) / 1000)
    : null;

  sendJson(res, 200, {
    status: openCircuits.length === 0 ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    eventBuffer: {
      size: events.length,
    },
    memoryCache: memCache,
    circuitBreakers: {
      total: Object.keys(circuitBreakers).length,
      open: openCircuits.length,
      openIds: openCircuits,
    },
    data: {
      newestEventAge: dataAgeSeconds ? `${dataAgeSeconds}s` : 'aucune donnée',
      newestEventTimestamp: newestEvent ? new Date(newestEvent).toISOString() : null,
    },
  });
}

// ─── Routeur HTTP ─────────────────────────────────────────────────────────────

function createRouter(): http.RequestListener {
  return (req, res) => {
    const url = req.url ?? '/';
    const pathname = url.split('?')[0];
    const query = parseQuery(url);

    // Route /api/feed
    if (pathname === '/api/feed') {
      return handleFeed(req, res, query);
    }

    // Route /api/threats
    if (pathname === '/api/threats') {
      return handleThreats(res);
    }

    // Route /api/cve/:id
    const cveMatch = pathname.match(/^\/api\/cve\/([^/]+)$/);
    if (cveMatch?.[1]) {
      return handleCve(res, cveMatch[1]);
    }

    // Route /api/stats
    if (pathname === '/api/stats') {
      return handleStats(res);
    }

    // Route /api/health
    if (pathname === '/api/health') {
      return handleHealth(res);
    }

    // 404
    sendJson(res, 404, {
      error: 'Route non trouvée',
      availableRoutes: [
        'GET /api/feed',
        'GET /api/feed?type=NEWS|VULNERABILITY|IOC|ADVISORY|RANSOMWARE',
        'GET /api/feed?severity=critical|high|medium|low|info',
        'GET /api/threats',
        'GET /api/cve/:id',
        'GET /api/stats',
        'GET /api/health',
      ],
    });
  };
}

// ─── Démarrage ────────────────────────────────────────────────────────────────

function main(): void {
  // Démarrer la boucle de polling
  startPollLoop(async (newEvents) => {
    const urgentEvents = newEvents.filter((e) => e.isUrgent);
    if (urgentEvents.length > 0) {
      console.warn(
        `[index] ⚠️  ${urgentEvents.length} événements URGENTS détectés:`,
        urgentEvents.map((e) => `[${e.severity.toUpperCase()}] ${e.title}`).join(', ')
      );
    }
  });

  // Démarrer le serveur HTTP
  const server = http.createServer(createRouter());

  server.listen(PORT, () => {
    console.info(`[index] 🚀 Moteur de veille cybersécurité démarré sur le port ${PORT}`);
    console.info(`[index] API disponible sur http://localhost:${PORT}/api/health`);
  });

  // Gestion propre des signaux de terminaison
  const shutdown = () => {
    console.info('[index] Arrêt du serveur...');
    server.close(() => process.exit(0));
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main();

/**
 * Example integrator backend.
 *
 * This is what "your backend" looks like in the GhostID docs: a plain Fastify
 * app whose protected routes are guarded by @ghostid/verify. The demo SPA
 * signs a request with ghost.getSessionHeaders() and calls /api/my-app/feed;
 * the preHandler forwards the headers to the GhostID server for verification
 * and attaches the authenticated identity to req.ghostid.
 *
 * Run alongside the GhostID server and demo:
 *   pnpm dev:api   (listens on :8788, expects GhostID on :8787)
 */

import cors from '@fastify/cors';
import { type GhostIDSession, GhostIDVerifier } from '@ghostid/verify';
import Fastify from 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    ghostid?: GhostIDSession;
  }
}

const GHOSTID_URL = process.env.GHOSTID_URL ?? 'http://localhost:8787';
const DEMO_ORIGIN = process.env.DEMO_ORIGIN ?? 'http://localhost:5173';
const PORT = Number(process.env.PORT ?? 8788);

const verifier = new GhostIDVerifier({ serverUrl: GHOSTID_URL });
const requireGhostID = verifier.fastifyPreHandler();

const app = Fastify({ logger: true });

await app.register(cors, {
  origin: DEMO_ORIGIN,
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-GhostID-Nonce',
    'X-GhostID-Signature',
    'X-GhostID-Timestamp',
  ],
});

app.get('/api/my-app/feed', { preHandler: [requireGhostID] }, async req => {
  // requireGhostID replied 401 already if verification failed
  const { userId, deviceId, sessionId, expiresAt } = req.ghostid as GhostIDSession;
  return {
    verifiedBy: '@ghostid/verify -> POST /api/sessions/verify',
    session: { userId, deviceId, sessionId, expiresAt },
    feed: [
      { id: 1, text: 'This response came from the example backend, not the GhostID server.' },
      { id: 2, text: 'It verified your signed headers without ever seeing your keys.' },
    ],
  };
});

await app.listen({ port: PORT, host: '0.0.0.0' });

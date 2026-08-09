/**
 * Example integrator backend.
 *
 * This is what "your backend" looks like in the Ignoti docs: a plain Fastify
 * app whose protected routes are guarded by @ignoti/verify. The demo SPA
 * signs a request with ignoti.getSessionHeaders() and calls /api/my-app/feed;
 * the preHandler forwards the headers to the Ignoti server for verification
 * and attaches the authenticated identity to req.ignoti.
 *
 * Run alongside the Ignoti server and demo:
 *   pnpm dev:api   (listens on :8788, expects Ignoti on :8787)
 */

import cors from '@fastify/cors';
import { type IgnotiSession, IgnotiVerifier } from '@ignoti/verify';
import Fastify from 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    ignoti?: IgnotiSession;
  }
}

const IGNOTI_URL = process.env.IGNOTI_URL ?? 'http://localhost:8787';
const DEMO_ORIGIN = process.env.DEMO_ORIGIN ?? 'http://localhost:5173';
const PORT = Number(process.env.PORT ?? 8788);

const verifier = new IgnotiVerifier({ serverUrl: IGNOTI_URL });
const requireIgnoti = verifier.fastifyPreHandler();

const app = Fastify({ logger: true });

await app.register(cors, {
  origin: DEMO_ORIGIN,
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Ignoti-Nonce',
    'X-Ignoti-Signature',
    'X-Ignoti-Timestamp',
  ],
});

app.get('/api/my-app/feed', { preHandler: [requireIgnoti] }, async req => {
  // requireIgnoti replied 401 already if verification failed
  const { userId, deviceId, sessionId, expiresAt } = req.ignoti as IgnotiSession;
  return {
    verifiedBy: '@ignoti/verify -> POST /api/sessions/verify',
    session: { userId, deviceId, sessionId, expiresAt },
    feed: [
      { id: 1, text: 'This response came from the example backend, not the Ignoti server.' },
      { id: 2, text: 'It verified your signed headers without ever seeing your keys.' },
    ],
  };
});

await app.listen({ port: PORT, host: '0.0.0.0' });

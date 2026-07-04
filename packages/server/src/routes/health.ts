import type { FastifyInstance } from 'fastify';
import { ROUTES } from '../constants.js';
import { sql } from '../db/client.js';

// Cache the probe so health check bursts don't each take a pool connection.
const PROBE_TTL_MS = 5000;
let lastProbe: { at: number; ok: boolean } | null = null;
let inFlight: Promise<boolean> | null = null;

async function probeDb(): Promise<boolean> {
  if (lastProbe && Date.now() - lastProbe.at < PROBE_TTL_MS) {
    return lastProbe.ok;
  }
  if (!inFlight) {
    inFlight = sql`SELECT 1`
      .then(
        () => true,
        () => false
      )
      .then(ok => {
        lastProbe = { at: Date.now(), ok };
        inFlight = null;
        return ok;
      });
  }
  return inFlight;
}

export async function registerHealthRoutes(app: FastifyInstance) {
  app.get(ROUTES.HEALTH, async (_req, reply) => {
    if (!(await probeDb())) {
      return reply.status(503).send({ status: 'error' });
    }
    return { status: 'ok' };
  });
}

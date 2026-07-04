import type { FastifyInstance } from 'fastify';
import { ROUTES } from '../constants.js';
import { sql } from '../db/client.js';

export const HEALTH_PROBE_TTL_MS = 5000;
export const HEALTH_PROBE_TIMEOUT_MS = 2000;

async function probeWithTimeout(): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<boolean>(resolve => {
    timer = setTimeout(() => resolve(false), HEALTH_PROBE_TIMEOUT_MS);
  });
  const query = sql`SELECT 1`.then(
    () => true,
    () => false
  );
  try {
    return await Promise.race([query, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export async function registerHealthRoutes(app: FastifyInstance) {
  let lastProbe: { at: number; ok: boolean } | null = null;
  let inFlight: Promise<boolean> | null = null;

  async function probeDb(): Promise<boolean> {
    if (lastProbe && Date.now() - lastProbe.at < HEALTH_PROBE_TTL_MS) {
      return lastProbe.ok;
    }
    if (!inFlight) {
      inFlight = probeWithTimeout().then(ok => {
        lastProbe = { at: Date.now(), ok };
        inFlight = null;
        return ok;
      });
    }
    return inFlight;
  }

  app.get(ROUTES.HEALTH, async (_req, reply) => {
    if (!(await probeDb())) {
      return reply.status(503).send({ status: 'error' });
    }
    return { status: 'ok' };
  });
}

import type { FastifyInstance } from 'fastify';
import { ROUTES } from '../constants';
import { sql } from '../db/client.js';

export async function registerHealthRoutes(app: FastifyInstance) {
  app.get(ROUTES.HEALTH, async (_req, reply) => {
    try {
      await sql`SELECT 1`;
    } catch {
      return reply.status(503).send({ status: 'error', detail: 'database unreachable' });
    }
    return { status: 'ok' };
  });
}

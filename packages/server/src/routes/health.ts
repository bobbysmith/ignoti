import type { FastifyInstance } from 'fastify';
import { ROUTES } from '../constants';

export async function registerHealthRoutes(app: FastifyInstance) {
  app.get(ROUTES.HEALTH, async () => ({ status: 'ok' }));
}

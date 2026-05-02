import Fastify from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ROUTES } from '../../constants';
import { registerHealthRoutes } from '../../routes/health.js';

const { mockSql } = vi.hoisted(() => ({ mockSql: vi.fn() }));

vi.mock('../../db/client.js', () => ({ sql: mockSql }));

const app = Fastify();

describe('GET /health', () => {
  beforeAll(async () => {
    await app.register(registerHealthRoutes);
    await app.ready();
  });

  afterAll(() => app.close());

  afterEach(() => vi.resetAllMocks());

  describe('database reachable', () => {
    it('returns 200 with { status: "ok" }', async () => {
      mockSql.mockResolvedValue([{ '?column?': 1 }]);
      const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ status: 'ok' });
    });
  });

  describe('database unreachable', () => {
    it('returns 503 with { status: "error" }', async () => {
      mockSql.mockRejectedValue(new Error('connection refused'));
      const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      expect(res.statusCode).toBe(503);
      expect(res.json()).toMatchObject({ status: 'error' });
    });
  });
});

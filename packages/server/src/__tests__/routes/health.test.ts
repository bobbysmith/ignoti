import Fastify from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ROUTES } from '../../constants';
import { registerHealthRoutes } from '../../routes/health.js';

const { mockSql } = vi.hoisted(() => ({ mockSql: vi.fn() }));

vi.mock('../../db/client.js', () => ({ sql: mockSql }));

const app = Fastify();

describe('GET /health', () => {
  beforeAll(async () => {
    vi.useFakeTimers();
    await app.register(registerHealthRoutes);
    await app.ready();
  });

  afterAll(async () => {
    vi.useRealTimers();
    await app.close();
  });

  afterEach(() => {
    vi.resetAllMocks();
    // Step past the probe TTL so each test starts with a stale cache
    vi.advanceTimersByTime(5001);
  });

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

  describe('probe caching', () => {
    it('does not re-query the database within the cache window', async () => {
      mockSql.mockResolvedValue([{ '?column?': 1 }]);
      await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      expect(res.statusCode).toBe(200);
      expect(mockSql).toHaveBeenCalledTimes(1);
    });

    it('serves the cached error state within the cache window', async () => {
      mockSql.mockRejectedValue(new Error('connection refused'));
      await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      mockSql.mockResolvedValue([{ '?column?': 1 }]);
      const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      expect(res.statusCode).toBe(503);
      expect(mockSql).toHaveBeenCalledTimes(1);
    });

    it('re-queries the database after the cache window expires', async () => {
      mockSql.mockResolvedValue([{ '?column?': 1 }]);
      await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      vi.advanceTimersByTime(5001);
      mockSql.mockRejectedValue(new Error('connection refused'));
      const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      expect(res.statusCode).toBe(503);
      expect(mockSql).toHaveBeenCalledTimes(2);
    });

    it('shares a single in-flight probe across concurrent requests', async () => {
      mockSql.mockResolvedValue([{ '?column?': 1 }]);
      const [a, b] = await Promise.all([
        app.inject({ method: 'GET', url: ROUTES.HEALTH }),
        app.inject({ method: 'GET', url: ROUTES.HEALTH }),
      ]);
      expect(a.statusCode).toBe(200);
      expect(b.statusCode).toBe(200);
      expect(mockSql).toHaveBeenCalledTimes(1);
    });
  });
});

import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ROUTES } from '../../constants';
import {
  HEALTH_PROBE_TIMEOUT_MS,
  HEALTH_PROBE_TTL_MS,
  registerHealthRoutes,
} from '../../routes/health.js';

const { mockSql } = vi.hoisted(() => ({ mockSql: vi.fn() }));

vi.mock('../../db/client.js', () => ({ sql: mockSql }));

describe('GET /health', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = Fastify();
    await app.register(registerHealthRoutes);
    await app.ready();
  });

  afterEach(async () => {
    vi.useRealTimers();
    await app.close();
    vi.resetAllMocks();
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

  describe('probe timeout', () => {
    it('returns 503 when the probe hangs past the timeout', async () => {
      vi.useFakeTimers();
      mockSql.mockReturnValue(new Promise(() => {}));
      const pending = app.inject({ method: 'GET', url: ROUTES.HEALTH });
      await vi.advanceTimersByTimeAsync(HEALTH_PROBE_TIMEOUT_MS + 1);
      const res = await pending;
      expect(res.statusCode).toBe(503);
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
      vi.useFakeTimers();
      mockSql.mockResolvedValue([{ '?column?': 1 }]);
      await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      vi.advanceTimersByTime(HEALTH_PROBE_TTL_MS + 1);
      mockSql.mockRejectedValue(new Error('connection refused'));
      const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
      expect(res.statusCode).toBe(503);
      expect(mockSql).toHaveBeenCalledTimes(2);
    });

    it('shares a single in-flight probe across concurrent requests', async () => {
      let resolveProbe!: (rows: unknown) => void;
      mockSql.mockReturnValue(
        new Promise(resolve => {
          resolveProbe = resolve;
        })
      );
      const a = app.inject({ method: 'GET', url: ROUTES.HEALTH });
      const b = app.inject({ method: 'GET', url: ROUTES.HEALTH });
      // Let both handlers reach the probe before it resolves
      await new Promise(resolve => setImmediate(resolve));
      resolveProbe([{ '?column?': 1 }]);
      const [resA, resB] = await Promise.all([a, b]);
      expect(resA.statusCode).toBe(200);
      expect(resB.statusCode).toBe(200);
      expect(mockSql).toHaveBeenCalledTimes(1);
    });
  });
});

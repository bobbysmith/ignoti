import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ROUTES } from '../../constants';
import { registerHealthRoutes } from '../../routes/health.js';

const app = Fastify();

describe('GET /health', () => {
  beforeAll(async () => {
    await app.register(registerHealthRoutes);
    await app.ready();
  });

  afterAll(() => app.close());

  it('returns 200 with { status: "ok" }', async () => {
    const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('ignores request body', async () => {
    const res = await app.inject({ method: 'GET', url: ROUTES.HEALTH, body: { foo: 'bar' } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('ignores request headers', async () => {
    const res = await app.inject({
      method: 'GET',
      url: ROUTES.HEALTH,
      headers: { 'x-custom': 'value' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });
});

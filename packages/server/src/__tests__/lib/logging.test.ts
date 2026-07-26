import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';
import { reqLogSerializer } from '../../lib/logging.js';

describe('reqLogSerializer', () => {
  it('keeps only method and url', () => {
    const req = {
      method: 'DELETE',
      url: '/api/sessions/abc',
      ip: '203.0.113.7',
      socket: { remoteAddress: '203.0.113.7', remotePort: 54321 },
      headers: { 'x-forwarded-for': '203.0.113.7' },
    } as unknown as FastifyRequest;

    const out = reqLogSerializer(req);

    expect(out).toEqual({ method: 'DELETE', url: '/api/sessions/abc' });
    expect(Object.keys(out).sort()).toEqual(['method', 'url']);
  });

  it('does not leak any client-IP field', () => {
    const req = {
      method: 'GET',
      url: '/api/devices',
      ip: '198.51.100.9',
      socket: { remoteAddress: '198.51.100.9' },
    } as unknown as FastifyRequest;

    const out = reqLogSerializer(req) as Record<string, unknown>;

    expect(out).not.toHaveProperty('remoteAddress');
    expect(out).not.toHaveProperty('remotePort');
    expect(out).not.toHaveProperty('ip');
    expect(JSON.stringify(out)).not.toContain('198.51.100.9');
  });
});

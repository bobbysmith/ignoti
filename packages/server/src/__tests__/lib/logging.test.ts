import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';
import { errSummary, reqLogSerializer } from '../../lib/logging.js';

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

describe('errSummary', () => {
  it('keeps name, code, and message only', () => {
    const err = Object.assign(new Error('"exp" claim timestamp check failed'), {
      name: 'JWTExpired',
      code: 'ERR_JWT_EXPIRED',
      payload: { userId: 'u-1', credentialId: 'cred-1', challenge: 'chal' },
      detail: 'Key (credential_id)=(cred-1) already exists.',
    });
    expect(errSummary(err)).toEqual({
      name: 'JWTExpired',
      code: 'ERR_JWT_EXPIRED',
      message: '"exp" claim timestamp check failed',
    });
  });

  it('omits a non-string code', () => {
    const err = Object.assign(new Error('boom'), { code: 42 });
    expect(errSummary(err).code).toBeUndefined();
  });

  it('does not serialize non-Error values', () => {
    expect(errSummary({ secret: 'x' })).toEqual({ message: 'non-error thrown' });
  });
});

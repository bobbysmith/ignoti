import cookie from '@fastify/cookie';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { ERROR_CODES } from '../../constants';
import {
  getSessionsForUser,
  revokeAllSessionsForUser,
  revokeSessionForUser,
} from '../../db/queries/sessions.js';
import {
  registerSessionAuthPlugin,
  requireSession,
  verifySessionAuth,
} from '../../plugins/session-auth.js';
import { registerSessionRoutes } from '../../routes/sessions.js';

vi.mock('../../config.js', () => ({
  config: {
    RP_ID: 'localhost',
    RP_NAME: 'GhostID',
    RP_ORIGIN: ['http://localhost:5173'],
    CHALLENGE_TTL_SECONDS: 300,
    SESSION_TTL_SECONDS: 86400,
    LOG_LEVEL: 'silent',
  },
}));
vi.mock('../../db/queries/sessions.js');
vi.mock('../../plugins/session-auth.js', () => ({
  registerSessionAuthPlugin: (app: FastifyInstance) => {
    app.decorateRequest('sessionContext', null);
  },
  requireSession: vi.fn(async (req: FastifyRequest) => {
    req.sessionContext = { sessionId: SESSION_ID, userId: USER_ID, deviceId: DEVICE_ID };
  }),
  verifySessionAuth: vi.fn(),
}));

const SESSION_ID = '550e8400-e29b-41d4-a716-446655440001';
const OTHER_SESSION_ID = '550e8400-e29b-41d4-a716-446655440002';
const USER_ID = 'user-uuid-1234';
const DEVICE_ID = '550e8400-e29b-41d4-a716-446655440000';

function makeSessionRow(overrides: Record<string, unknown> = {}) {
  return {
    id: SESSION_ID,
    device_id: DEVICE_ID,
    created_at: new Date('2024-01-01T00:00:00Z'),
    last_used_at: new Date('2024-01-02T00:00:00Z'),
    expires_at: new Date('2024-01-08T00:00:00Z'),
    ...overrides,
  };
}

let app: FastifyInstance;

describe('sessions', () => {
  beforeAll(async () => {
    app = Fastify({ logger: false });
    await app.register(cookie);
    registerSessionAuthPlugin(app);
    await app.register(registerSessionRoutes, { prefix: '/api/sessions' });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.mocked(requireSession).mockImplementation(async (req: FastifyRequest) => {
      req.sessionContext = { sessionId: SESSION_ID, userId: USER_ID, deviceId: DEVICE_ID };
    });
    vi.mocked(getSessionsForUser).mockReset();
    vi.mocked(revokeSessionForUser).mockReset();
    vi.mocked(revokeAllSessionsForUser).mockReset();
    vi.mocked(verifySessionAuth).mockReset();
  });

  describe('POST /api/sessions/verify', () => {
    const EXPIRES_AT = new Date('2024-01-08T00:00:00Z');

    function makeVerifyBody(overrides: Record<string, unknown> = {}) {
      return {
        method: 'GET',
        path: '/api/feed',
        authorization: `GhostID-Session ${SESSION_ID}`,
        nonce: crypto.randomUUID(),
        timestamp: String(Math.floor(Date.now() / 1000)),
        signature: 'c2lnbmF0dXJl',
        ...overrides,
      };
    }

    function postVerify(body: Record<string, unknown>) {
      return app.inject({ method: 'POST', url: '/api/sessions/verify', payload: body });
    }

    describe('body validation', () => {
      it.each([
        'method',
        'path',
        'authorization',
        'nonce',
        'timestamp',
        'signature',
      ])('returns 400 INVALID_INPUT when %s is missing', async field => {
        const body = makeVerifyBody();
        delete body[field as keyof typeof body];
        const res = await postVerify(body);
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
        expect(verifySessionAuth).not.toHaveBeenCalled();
      });

      it('returns 400 INVALID_INPUT when a field is empty', async () => {
        const res = await postVerify(makeVerifyBody({ signature: '' }));
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('invalid session', () => {
      it('returns 200 with valid=false and the error code', async () => {
        vi.mocked(verifySessionAuth).mockResolvedValue({
          ok: false,
          code: ERROR_CODES.SESSION_NOT_FOUND,
        });
        const res = await postVerify(makeVerifyBody());
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ valid: false, error: ERROR_CODES.SESSION_NOT_FOUND });
      });

      it('surfaces nonce replay as valid=false SESSION_NONCE_USED', async () => {
        vi.mocked(verifySessionAuth).mockResolvedValue({
          ok: false,
          code: ERROR_CODES.SESSION_NONCE_USED,
        });
        const res = await postVerify(makeVerifyBody());
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ valid: false, error: ERROR_CODES.SESSION_NONCE_USED });
      });
    });

    describe('valid session', () => {
      beforeEach(() => {
        vi.mocked(verifySessionAuth).mockResolvedValue({
          ok: true,
          context: { sessionId: SESSION_ID, userId: USER_ID, deviceId: DEVICE_ID },
          expiresAt: EXPIRES_AT,
        });
      });

      it('returns 200 with valid=true and the session context', async () => {
        const res = await postVerify(makeVerifyBody());
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({
          valid: true,
          sessionId: SESSION_ID,
          userId: USER_ID,
          deviceId: DEVICE_ID,
          expiresAt: EXPIRES_AT.getTime(),
        });
      });

      it('passes the forwarded material to verifySessionAuth verbatim', async () => {
        const body = makeVerifyBody({ method: 'DELETE', path: '/api/things/42' });
        await postVerify(body);
        expect(verifySessionAuth).toHaveBeenCalledWith(
          {
            method: 'DELETE',
            path: '/api/things/42',
            authorization: body.authorization,
            nonce: body.nonce,
            timestamp: body.timestamp,
            signature: body.signature,
          },
          expect.anything()
        );
      });
    });
  });

  describe('GET /api/sessions', () => {
    describe('authentication', () => {
      it('returns 401 when requireSession rejects', async () => {
        vi.mocked(requireSession).mockImplementationOnce(
          async (_req: FastifyRequest, reply: FastifyReply) => {
            reply.code(401).send({ error: ERROR_CODES.MISSING_SESSION_HEADERS });
          }
        );
        const res = await app.inject({ method: 'GET', url: '/api/sessions' });
        expect(res.statusCode).toBe(401);
      });
    });

    describe('happy path', () => {
      it('returns 200 with empty sessions array when user has no sessions', async () => {
        vi.mocked(getSessionsForUser).mockResolvedValue([]);
        const res = await app.inject({ method: 'GET', url: '/api/sessions' });
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ sessions: [] });
      });

      it('maps db row fields to camelCase response', async () => {
        vi.mocked(getSessionsForUser).mockResolvedValue([makeSessionRow()]);
        const res = await app.inject({ method: 'GET', url: '/api/sessions' });
        const session = res.json().sessions[0];
        expect(session.id).toBe(SESSION_ID);
        expect(session.deviceId).toBe(DEVICE_ID);
        expect(session.createdAt).toBe('2024-01-01T00:00:00.000Z');
        expect(session.lastUsedAt).toBe('2024-01-02T00:00:00.000Z');
        expect(session.expiresAt).toBe('2024-01-08T00:00:00.000Z');
      });

      it('sets isCurrent=true for the session making the request', async () => {
        vi.mocked(getSessionsForUser).mockResolvedValue([makeSessionRow({ id: SESSION_ID })]);
        const res = await app.inject({ method: 'GET', url: '/api/sessions' });
        expect(res.json().sessions[0].isCurrent).toBe(true);
      });

      it('sets isCurrent=false for other sessions', async () => {
        vi.mocked(getSessionsForUser).mockResolvedValue([makeSessionRow({ id: OTHER_SESSION_ID })]);
        const res = await app.inject({ method: 'GET', url: '/api/sessions' });
        expect(res.json().sessions[0].isCurrent).toBe(false);
      });

      it('returns lastUsedAt as null when last_used_at is null', async () => {
        vi.mocked(getSessionsForUser).mockResolvedValue([makeSessionRow({ last_used_at: null })]);
        const res = await app.inject({ method: 'GET', url: '/api/sessions' });
        expect(res.json().sessions[0].lastUsedAt).toBeNull();
      });

      it('queries sessions for the authenticated userId', async () => {
        vi.mocked(getSessionsForUser).mockResolvedValue([]);
        await app.inject({ method: 'GET', url: '/api/sessions' });
        expect(getSessionsForUser).toHaveBeenCalledWith(USER_ID);
      });
    });
  });

  describe('DELETE /api/sessions/:id', () => {
    function deleteSession(id = OTHER_SESSION_ID) {
      return app.inject({ method: 'DELETE', url: `/api/sessions/${id}` });
    }

    describe('param validation', () => {
      it('returns 400 INVALID_INPUT when sessionId is not a UUID', async () => {
        const res = await deleteSession('not-a-uuid');
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('not found', () => {
      it('returns 404 SESSION_NOT_FOUND when session does not exist', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(false);
        const res = await deleteSession();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.SESSION_NOT_FOUND });
      });

      it('returns 404 SESSION_NOT_FOUND when session belongs to another user', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(false);
        const res = await deleteSession();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.SESSION_NOT_FOUND });
      });
    });

    describe('happy path', () => {
      it('returns 200 with { ok: true } on successful revocation', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(true);
        const res = await deleteSession();
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ ok: true });
      });

      it('calls revokeSessionForUser with targetSessionId and userId', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(true);
        await deleteSession(OTHER_SESSION_ID);
        expect(revokeSessionForUser).toHaveBeenCalledWith(OTHER_SESSION_ID, USER_ID);
      });

      it('allows revoking the current session (self-logout)', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(true);
        const res = await deleteSession(SESSION_ID);
        expect(res.statusCode).toBe(200);
        expect(revokeSessionForUser).toHaveBeenCalledWith(SESSION_ID, USER_ID);
      });

      it('clears the session cookie when revoking the current session', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(true);
        const res = await deleteSession(SESSION_ID);
        const raw = res.headers['set-cookie'];
        const cookieStr = Array.isArray(raw) ? raw[0] : (raw as string);
        expect(cookieStr).toMatch(/ghostid_session=(?:;|$| )/);
      });

      it('does not clear the session cookie when revoking a different session', async () => {
        vi.mocked(revokeSessionForUser).mockResolvedValue(true);
        const res = await deleteSession(OTHER_SESSION_ID);
        expect(res.headers['set-cookie']).toBeUndefined();
      });
    });
  });

  describe('DELETE /api/sessions', () => {
    function deleteAllSessions() {
      return app.inject({ method: 'DELETE', url: '/api/sessions' });
    }

    it('returns 200 with the number of revoked sessions', async () => {
      vi.mocked(revokeAllSessionsForUser).mockResolvedValue(4);
      const res = await deleteAllSessions();
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ revoked: 4 });
    });

    it('returns 0 when the user has no other active sessions', async () => {
      vi.mocked(revokeAllSessionsForUser).mockResolvedValue(0);
      const res = await deleteAllSessions();
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ revoked: 0 });
    });

    it('calls revokeAllSessionsForUser with the authenticated userId', async () => {
      vi.mocked(revokeAllSessionsForUser).mockResolvedValue(1);
      await deleteAllSessions();
      expect(revokeAllSessionsForUser).toHaveBeenCalledWith(USER_ID);
    });

    it('clears the session cookie', async () => {
      vi.mocked(revokeAllSessionsForUser).mockResolvedValue(1);
      const res = await deleteAllSessions();
      const raw = res.headers['set-cookie'];
      const cookieStr = Array.isArray(raw) ? raw[0] : (raw as string);
      expect(cookieStr).toMatch(/ghostid_session=(?:;|$| )/);
    });
  });
});

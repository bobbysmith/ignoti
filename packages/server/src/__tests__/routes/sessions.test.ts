import cookie from '@fastify/cookie';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { ERROR_CODES } from '../../constants';
import { getSessionsForUser, revokeSessionForUser } from '../../db/queries/sessions.js';
import { registerSessionAuthPlugin, requireSession } from '../../plugins/session-auth.js';
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
});

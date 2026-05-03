import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { ERROR_CODES, VALIDATION } from '../../constants';
import {
  getDeviceById,
  getDevicesForUser,
  revokeDeviceWithSessions,
} from '../../db/queries/devices.js';
import { getUserById } from '../../db/queries/users.js';
import { verifyDeviceBindingJWS } from '../../lib/root-jws.js';
import { registerSessionAuthPlugin, requireSession } from '../../plugins/session-auth.js';
import { registerDeviceRoutes } from '../../routes/devices.js';

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
vi.mock('../../db/queries/devices.js');
vi.mock('../../db/queries/users.js');
vi.mock('../../lib/root-jws.js');
vi.mock('../../plugins/session-auth.js', () => ({
  registerSessionAuthPlugin: (app: FastifyInstance) => {
    app.decorateRequest('sessionContext', null);
  },
  requireSession: vi.fn(async (req: FastifyRequest) => {
    req.sessionContext = { sessionId: SESSION_ID, userId: USER_ID, deviceId: DEVICE_ID };
  }),
}));

const SESSION_ID = 'session-uuid-5678';
const USER_ID = 'user-uuid-1234';
const DEVICE_ID = '550e8400-e29b-41d4-a716-446655440000';
const CREDENTIAL_ID = 'cred-id-base64url';
const ROOT_PUBLIC_KEY = 'root-pub-key-b64';
const VALID_ROOT_SIGNATURE = 'x'.repeat(64);
const SHORT_ROOT_SIGNATURE = 'x'.repeat(VALIDATION.MIN_ROOT_SIGNATURE_LENGTH - 1);
const LONG_ROOT_SIGNATURE = 'x'.repeat(VALIDATION.MAX_ROOT_SIGNATURE_LENGTH + 1);

function makeDeviceListItem(overrides: Record<string, unknown> = {}) {
  return {
    id: DEVICE_ID,
    credential_id: CREDENTIAL_ID,
    device_name: 'My Device',
    created_at: new Date('2024-01-01T00:00:00Z'),
    last_used_at: null,
    ...overrides,
  };
}

function makeDeviceWithUser(overrides: Record<string, unknown> = {}) {
  return { user_id: USER_ID, credential_id: CREDENTIAL_ID, ...overrides };
}

function makeUser(overrides: Record<string, unknown> = {}) {
  return { id: USER_ID, root_public_key: ROOT_PUBLIC_KEY, ...overrides };
}

let app: FastifyInstance;

describe('devices', () => {
  describe('GET /api/devices', () => {
    beforeAll(async () => {
      app = Fastify({ logger: false });
      registerSessionAuthPlugin(app);
      await app.register(registerDeviceRoutes, { prefix: '/api/devices' });
      await app.ready();
    });

    afterAll(async () => {
      await app.close();
    });

    beforeEach(() => {
      vi.mocked(requireSession).mockImplementation(async (req: FastifyRequest) => {
        req.sessionContext = { sessionId: SESSION_ID, userId: USER_ID, deviceId: DEVICE_ID };
      });
      vi.mocked(getDevicesForUser).mockReset();
    });

    describe('authentication', () => {
      it('returns 401 when requireSession rejects', async () => {
        vi.mocked(requireSession).mockImplementationOnce(
          async (_req: FastifyRequest, reply: FastifyReply) => {
            reply.code(401).send({ error: ERROR_CODES.MISSING_SESSION_HEADERS });
          }
        );
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.statusCode).toBe(401);
      });
    });

    describe('happy path', () => {
      it('returns 200 with empty devices array when user has no devices', async () => {
        vi.mocked(getDevicesForUser).mockResolvedValue([]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ devices: [] });
      });

      it('returns 200 with device list for the authenticated user', async () => {
        vi.mocked(getDevicesForUser).mockResolvedValue([makeDeviceListItem()]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.statusCode).toBe(200);
        expect(res.json().devices).toHaveLength(1);
      });

      it('maps credential_id → credentialId in the response', async () => {
        vi.mocked(getDevicesForUser).mockResolvedValue([makeDeviceListItem()]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.json().devices[0].credentialId).toBe(CREDENTIAL_ID);
      });

      it('maps device_name → deviceName in the response', async () => {
        vi.mocked(getDevicesForUser).mockResolvedValue([
          makeDeviceListItem({ device_name: 'Phone' }),
        ]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.json().devices[0].deviceName).toBe('Phone');
      });

      it('maps created_at → createdAt as ISO string', async () => {
        const created_at = new Date('2024-06-01T12:00:00.000Z');
        vi.mocked(getDevicesForUser).mockResolvedValue([makeDeviceListItem({ created_at })]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.json().devices[0].createdAt).toBe(created_at.toISOString());
      });

      it('maps last_used_at → lastUsedAt as ISO string when present', async () => {
        const last_used_at = new Date('2024-07-01T09:00:00.000Z');
        vi.mocked(getDevicesForUser).mockResolvedValue([makeDeviceListItem({ last_used_at })]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.json().devices[0].lastUsedAt).toBe(last_used_at.toISOString());
      });

      it('returns lastUsedAt as null when last_used_at is null', async () => {
        vi.mocked(getDevicesForUser).mockResolvedValue([
          makeDeviceListItem({ last_used_at: null }),
        ]);
        const res = await app.inject({ method: 'GET', url: '/api/devices' });
        expect(res.json().devices[0].lastUsedAt).toBeNull();
      });

      it('queries devices only for the authenticated userId', async () => {
        vi.mocked(getDevicesForUser).mockResolvedValue([]);
        await app.inject({ method: 'GET', url: '/api/devices' });
        expect(getDevicesForUser).toHaveBeenCalledWith(USER_ID);
      });
    });
  });

  describe('DELETE /api/devices/:id', () => {
    beforeAll(async () => {
      app = Fastify({ logger: false });
      registerSessionAuthPlugin(app);
      await app.register(registerDeviceRoutes, { prefix: '/api/devices' });
      await app.ready();
    });

    afterAll(async () => {
      await app.close();
    });

    beforeEach(() => {
      vi.mocked(getDeviceById).mockReset();
      vi.mocked(getUserById).mockReset();
      vi.mocked(verifyDeviceBindingJWS).mockReset();
      vi.mocked(revokeDeviceWithSessions).mockReset();
    });

    function deleteDevice(
      id = DEVICE_ID,
      body: Record<string, unknown> = { rootSignature: VALID_ROOT_SIGNATURE }
    ) {
      return app.inject({ method: 'DELETE', url: `/api/devices/${id}`, body });
    }

    describe('request validation', () => {
      it('returns 400 INVALID_INPUT when body is empty', async () => {
        const res = await deleteDevice(DEVICE_ID, {});
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootSignature is too short', async () => {
        const res = await deleteDevice(DEVICE_ID, { rootSignature: SHORT_ROOT_SIGNATURE });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootSignature is too long', async () => {
        const res = await deleteDevice(DEVICE_ID, { rootSignature: LONG_ROOT_SIGNATURE });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('device lookup', () => {
      it('returns 404 DEVICE_NOT_FOUND when getDeviceById returns undefined', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(undefined);
        const res = await deleteDevice();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.DEVICE_NOT_FOUND });
      });

      it('returns 404 DEVICE_NOT_FOUND when device is already revoked', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(undefined);
        const res = await deleteDevice();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.DEVICE_NOT_FOUND });
      });
    });

    describe('user lookup', () => {
      it('returns 404 USER_NOT_FOUND when getUserById returns undefined', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(makeDeviceWithUser());
        vi.mocked(getUserById).mockResolvedValue(undefined);
        const res = await deleteDevice();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.USER_NOT_FOUND });
      });
    });

    describe('root signature verification', () => {
      it('returns 401 INVALID_ROOT_SIGNATURE when verifyDeviceBindingJWS throws', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(makeDeviceWithUser());
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(verifyDeviceBindingJWS).mockRejectedValue(new Error('bad sig'));
        const res = await deleteDevice();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_ROOT_SIGNATURE });
      });

      it('passes purpose="revoke-device" to verifyDeviceBindingJWS', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(makeDeviceWithUser());
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
        vi.mocked(revokeDeviceWithSessions).mockResolvedValue(undefined);
        await deleteDevice();
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          VALID_ROOT_SIGNATURE,
          ROOT_PUBLIC_KEY,
          expect.objectContaining({ purpose: 'revoke-device' })
        );
      });

      it('passes deviceId as the challenge to verifyDeviceBindingJWS', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(makeDeviceWithUser());
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
        vi.mocked(revokeDeviceWithSessions).mockResolvedValue(undefined);
        await deleteDevice(DEVICE_ID);
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          expect.objectContaining({ challenge: DEVICE_ID })
        );
      });

      it('passes device.credential_id as credentialId to verifyDeviceBindingJWS', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(makeDeviceWithUser());
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
        vi.mocked(revokeDeviceWithSessions).mockResolvedValue(undefined);
        await deleteDevice();
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          expect.objectContaining({ credentialId: CREDENTIAL_ID })
        );
      });
    });

    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(getDeviceById).mockResolvedValue(makeDeviceWithUser());
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
        vi.mocked(revokeDeviceWithSessions).mockResolvedValue(undefined);
      });

      it('returns 200 with { ok: true }', async () => {
        const res = await deleteDevice();
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ ok: true });
      });

      it('calls revokeDeviceWithSessions with the correct deviceId', async () => {
        await deleteDevice();
        expect(revokeDeviceWithSessions).toHaveBeenCalledWith(DEVICE_ID);
      });
    });

    describe('param validation', () => {
      it('returns 400 INVALID_INPUT when deviceId is not a UUID', async () => {
        const res = await deleteDevice('not-a-uuid');
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });
  });
});

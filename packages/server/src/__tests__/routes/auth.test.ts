import cookie from '@fastify/cookie';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { ERROR_CODES, VALIDATION } from '../../constants';
import {
  consumeLoginChallenge,
  consumeRecoverChallenge,
  consumeRegisterChallenge,
  consumeSessionChallenge,
  insertLoginChallenge,
  insertRecoverChallenge,
  insertRegisterChallenge,
  insertTimingRecoverChallenge,
} from '../../db/queries/challenges.js';
import { getDeviceByCredentialId, getDeviceById, insertDevice } from '../../db/queries/devices.js';
import { incrementSignCountWithChallenge } from '../../db/queries/login.js';
import { insertSession, rebindSessionPublicKey } from '../../db/queries/sessions.js';
import { getUserById, getUserByRootPublicKey, upsertUser } from '../../db/queries/users.js';
import { buildRegistrationOptions, extractChallenge } from '../../helpers/auth.js';
import { decodeJwt, verifyDeviceBindingJWS } from '../../lib/root-jws.js';
import { verifySessionBindingJWS } from '../../lib/session-jws.js';
import { registerAuthRoutes } from '../../routes/auth.js';

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
vi.mock('../../db/queries/users.js');
vi.mock('../../db/queries/devices.js');
vi.mock('../../db/queries/challenges.js');
vi.mock('../../db/queries/login.js');
vi.mock('../../db/queries/sessions.js');
vi.mock('@simplewebauthn/server');
vi.mock('../../lib/root-jws.js');
vi.mock('../../lib/session-jws.js');
vi.mock('../../helpers/auth.js');

const VALID_USER_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const VALID_ROOT_PUBLIC_KEY = 'A'.repeat(32);
const VALID_ROOT_SIGNATURE = 'x'.repeat(64);
const VALID_CREDENTIAL_ID = 'credential-id-base64url';
const VALID_CHALLENGE = 'challenge-base64url-value';
const VALID_SESSION_BINDING = 'x'.repeat(64);
const VALID_DEVICE_ID = 'device-uuid-abcd';
const VALID_SESSION_PUBLIC_KEY = 'session-pub-key-b64';
const VALID_SESSION_CHALLENGE = 'session-challenge-value';
const SHORT_ROOT_PUBLIC_KEY = 'A'.repeat(VALIDATION.MIN_ROOT_PUBLIC_KEY_LENGTH - 1);
const LONG_ROOT_PUBLIC_KEY = 'A'.repeat(VALIDATION.MAX_ROOT_PUBLIC_KEY_LENGTH + 1);
const SHORT_ROOT_SIGNATURE = 'x'.repeat(VALIDATION.MIN_ROOT_SIGNATURE_LENGTH - 1);
const LONG_ROOT_SIGNATURE = 'x'.repeat(VALIDATION.MAX_ROOT_SIGNATURE_LENGTH + 1);
const SHORT_SESSION_BINDING = 'x'.repeat(VALIDATION.MIN_SESSION_BINDING_LENGTH - 1);
const LONG_SESSION_BINDING = 'x'.repeat(VALIDATION.MAX_SESSION_BINDING_LENGTH + 1);
const REGISTER_URL = '/api/auth/register';
const DEVICES_URL = '/api/auth/register/device';
const LOGIN_URL = '/api/auth/login';
const CHALLENGE_URL = '/api/auth/challenge';
const SESSION_URL = '/api/auth/session';
const SESSION_RESTORE_URL = '/api/auth/session/restore';
const RECOVER_URL = '/api/auth/recover';
const VALID_SESSION_ID = '550e8400-e29b-41d4-a716-446655440001';

const VALID_REGISTRATION_RESPONSE = {
  id: VALID_CREDENTIAL_ID,
  rawId: VALID_CREDENTIAL_ID,
  type: 'public-key' as const,
  response: {
    clientDataJSON: 'clientdata-placeholder',
    attestationObject: 'attestation-placeholder',
  },
};

const VALID_ASSERTION = {
  id: VALID_CREDENTIAL_ID,
  rawId: VALID_CREDENTIAL_ID,
  type: 'public-key' as const,
  response: {
    clientDataJSON: 'clientdata-placeholder',
    authenticatorData: 'authdata-placeholder',
    signature: 'sig-placeholder',
  },
};

function makeUser() {
  return { id: VALID_USER_ID, root_public_key: VALID_ROOT_PUBLIC_KEY };
}

function makeDevice() {
  return {
    id: VALID_DEVICE_ID,
    credential_id: VALID_CREDENTIAL_ID,
    passkey_public_key: 'passkey-pub-b64',
    sign_count: 0n,
    transports: null,
  };
}

function makeRegistrationVerification() {
  return {
    verified: true,
    registrationInfo: {
      credential: {
        id: VALID_CREDENTIAL_ID,
        publicKey: new Uint8Array([1, 2, 3]),
        counter: 0,
      },
    },
  };
}

function makeAuthVerification() {
  return { verified: true, authenticationInfo: { newCounter: 1 } };
}

function makeSession() {
  return { id: 'session-id-1234', expires_at: new Date(Date.now() + 86_400_000) };
}

let app: FastifyInstance;

describe('auth', () => {
  beforeAll(async () => {
    app = Fastify({ logger: false });
    await app.register(cookie);
    await app.register(registerAuthRoutes, { prefix: '/api/auth' });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('POST /api/auth/register', () => {
    describe('request validation', () => {
      it('returns 400 INVALID_INPUT when body is empty', async () => {
        const res = await app.inject({ method: 'POST', url: REGISTER_URL, body: {} });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootPublicKey is missing', async () => {
        const res = await app.inject({
          method: 'POST',
          url: REGISTER_URL,
          body: { other: 'field' },
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootPublicKey is shorter than MIN_ROOT_PUBLIC_KEY_LENGTH', async () => {
        const res = await app.inject({
          method: 'POST',
          url: REGISTER_URL,
          body: { rootPublicKey: SHORT_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootPublicKey exceeds MAX_ROOT_PUBLIC_KEY_LENGTH', async () => {
        const res = await app.inject({
          method: 'POST',
          url: REGISTER_URL,
          body: { rootPublicKey: LONG_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(upsertUser).mockResolvedValue({ id: VALID_USER_ID });
        vi.mocked(buildRegistrationOptions).mockResolvedValue({
          challenge: VALID_CHALLENGE,
        } as never);
        vi.mocked(insertRegisterChallenge).mockResolvedValue(undefined);
      });

      it('calls upsertUser with the provided rootPublicKey', async () => {
        await app.inject({
          method: 'POST',
          url: REGISTER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(upsertUser).toHaveBeenCalledWith(VALID_ROOT_PUBLIC_KEY);
      });

      it('returns 200 with userId and WebAuthn options', async () => {
        const res = await app.inject({
          method: 'POST',
          url: REGISTER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({
          userId: VALID_USER_ID,
          options: { challenge: VALID_CHALLENGE },
        });
      });

      it('idempotent: re-posting same rootPublicKey returns the existing userId', async () => {
        vi.mocked(upsertUser).mockResolvedValue({ id: VALID_USER_ID });
        const res = await app.inject({
          method: 'POST',
          url: REGISTER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(res.json().userId).toBe(VALID_USER_ID);
      });
    });
  });

  describe('POST /api/auth/register/device', () => {
    function registerDevice(body: Record<string, unknown> = {}) {
      return app.inject({
        method: 'POST',
        url: DEVICES_URL,
        body: {
          userId: VALID_USER_ID,
          registrationResponse: VALID_REGISTRATION_RESPONSE,
          rootSignature: VALID_ROOT_SIGNATURE,
          ...body,
        },
      });
    }

    describe('request validation', () => {
      it('returns 400 INVALID_INPUT when body is empty', async () => {
        const res = await app.inject({
          method: 'POST',
          url: DEVICES_URL,
          body: {},
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when userId is not a valid UUID', async () => {
        const res = await registerDevice({ userId: 'not-a-uuid' });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when registrationResponse is missing required fields', async () => {
        const res = await registerDevice({ registrationResponse: { id: VALID_CREDENTIAL_ID } });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootSignature is too short', async () => {
        const res = await registerDevice({ rootSignature: SHORT_ROOT_SIGNATURE });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootSignature is too long', async () => {
        const res = await registerDevice({ rootSignature: LONG_ROOT_SIGNATURE });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when deviceName exceeds MAX_DEVICE_NAME_LENGTH', async () => {
        const res = await registerDevice({
          deviceName: 'x'.repeat(VALIDATION.MAX_DEVICE_NAME_LENGTH + 1),
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('user lookup', () => {
      it('returns 404 USER_NOT_FOUND when getUserById returns undefined', async () => {
        vi.mocked(getUserById).mockResolvedValue(undefined);
        const res = await registerDevice();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.USER_NOT_FOUND });
      });
    });

    describe('challenge extraction', () => {
      beforeEach(() => {
        vi.mocked(getUserById).mockResolvedValue(makeUser());
      });

      it('returns 400 INVALID_INPUT when extractChallenge throws', async () => {
        vi.mocked(extractChallenge).mockImplementation(() => {
          throw new Error('malformed clientDataJSON');
        });
        const res = await registerDevice();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('challenge consumption', () => {
      beforeEach(() => {
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
      });

      it('returns 400 INVALID_OR_EXPIRED_CHALLENGE when consumeRegisterChallenge returns false', async () => {
        vi.mocked(consumeRegisterChallenge).mockResolvedValue(false);
        const res = await registerDevice();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_OR_EXPIRED_CHALLENGE });
      });
    });

    describe('JWS purpose extraction', () => {
      beforeEach(() => {
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
        vi.mocked(consumeRegisterChallenge).mockResolvedValue(true);
        vi.mocked(consumeRecoverChallenge).mockResolvedValue(true);
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
        vi.mocked(verifyRegistrationResponse).mockResolvedValue(
          makeRegistrationVerification() as never
        );
        vi.mocked(insertDevice).mockResolvedValue({ id: VALID_DEVICE_ID });
      });

      it('defaults purpose to "register-device" when decodeJwt throws', async () => {
        vi.mocked(decodeJwt).mockImplementation(() => {
          throw new Error('malformed');
        });
        await registerDevice();
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          expect.objectContaining({ purpose: 'register-device' })
        );
      });

      it('uses "recover-device" purpose and consumes a recover challenge when JWS contains that purpose', async () => {
        vi.mocked(decodeJwt).mockReturnValue({ purpose: 'recover-device' } as never);
        await registerDevice();
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          expect.objectContaining({ purpose: 'recover-device' })
        );
        expect(consumeRecoverChallenge).toHaveBeenCalledWith(VALID_CHALLENGE, VALID_USER_ID);
        expect(consumeRegisterChallenge).not.toHaveBeenCalled();
      });

      it('defaults to "register-device" and consumes a register challenge when purpose is not an allowed value', async () => {
        vi.mocked(decodeJwt).mockReturnValue({ purpose: 'invalid-purpose' } as never);
        await registerDevice();
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          expect.objectContaining({ purpose: 'register-device' })
        );
        expect(consumeRegisterChallenge).toHaveBeenCalledWith(VALID_CHALLENGE, VALID_USER_ID);
        expect(consumeRecoverChallenge).not.toHaveBeenCalled();
      });

      it('defaults to "register-device" when purpose in JWS is a non-string value', async () => {
        vi.mocked(decodeJwt).mockReturnValue({ purpose: 42 } as never);
        await registerDevice();
        expect(verifyDeviceBindingJWS).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          expect.objectContaining({ purpose: 'register-device' })
        );
        expect(consumeRegisterChallenge).toHaveBeenCalledWith(VALID_CHALLENGE, VALID_USER_ID);
        expect(consumeRecoverChallenge).not.toHaveBeenCalled();
      });
    });

    describe('root signature verification', () => {
      beforeEach(() => {
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
        vi.mocked(consumeRegisterChallenge).mockResolvedValue(true);
        vi.mocked(decodeJwt).mockReturnValue({ purpose: 'register-device' } as never);
      });

      it('returns 401 INVALID_ROOT_SIGNATURE when verifyDeviceBindingJWS throws', async () => {
        vi.mocked(verifyDeviceBindingJWS).mockRejectedValue(new Error('bad sig'));
        const res = await registerDevice();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_ROOT_SIGNATURE });
      });
    });

    describe('WebAuthn attestation', () => {
      beforeEach(() => {
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
        vi.mocked(consumeRegisterChallenge).mockResolvedValue(true);
        vi.mocked(decodeJwt).mockReturnValue({ purpose: 'register-device' } as never);
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
      });

      it('returns 401 ATTESTATION_VERIFICATION_FAILED when verifyRegistrationResponse throws', async () => {
        vi.mocked(verifyRegistrationResponse).mockRejectedValue(new Error('attestation error'));
        const res = await registerDevice();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ATTESTATION_VERIFICATION_FAILED });
      });

      it('returns 401 ATTESTATION_VERIFICATION_FAILED when verified is false', async () => {
        vi.mocked(verifyRegistrationResponse).mockResolvedValue({ verified: false } as never);
        const res = await registerDevice();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ATTESTATION_VERIFICATION_FAILED });
      });

      it('returns 401 ATTESTATION_VERIFICATION_FAILED when registrationInfo is null', async () => {
        vi.mocked(verifyRegistrationResponse).mockResolvedValue({
          verified: true,
          registrationInfo: null,
        } as never);
        const res = await registerDevice();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ATTESTATION_VERIFICATION_FAILED });
      });
    });

    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(getUserById).mockResolvedValue(makeUser());
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
        vi.mocked(consumeRegisterChallenge).mockResolvedValue(true);
        vi.mocked(decodeJwt).mockReturnValue({ purpose: 'register-device' } as never);
        vi.mocked(verifyDeviceBindingJWS).mockResolvedValue(undefined as never);
        vi.mocked(verifyRegistrationResponse).mockResolvedValue(
          makeRegistrationVerification() as never
        );
        vi.mocked(insertDevice).mockResolvedValue({ id: VALID_DEVICE_ID });
      });

      it('returns 200 with deviceId and credentialId', async () => {
        const res = await registerDevice();
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({
          deviceId: VALID_DEVICE_ID,
          credentialId: VALID_CREDENTIAL_ID,
        });
      });

      it('inserts device with correct credentialId', async () => {
        await registerDevice();
        expect(insertDevice).toHaveBeenCalledWith(
          expect.objectContaining({ credentialId: VALID_CREDENTIAL_ID })
        );
      });

      it('stores transports as null when response.transports is undefined', async () => {
        await registerDevice();
        expect(insertDevice).toHaveBeenCalledWith(expect.objectContaining({ transports: null }));
      });

      it('stores transports array when response.transports is present', async () => {
        const transports = ['internal', 'hybrid'];
        await registerDevice({
          registrationResponse: {
            ...VALID_REGISTRATION_RESPONSE,
            response: { ...VALID_REGISTRATION_RESPONSE.response, transports },
          },
        });
        expect(insertDevice).toHaveBeenCalledWith(expect.objectContaining({ transports }));
      });

      it('stores transports as null when response.transports is an empty array', async () => {
        await registerDevice({
          registrationResponse: {
            ...VALID_REGISTRATION_RESPONSE,
            response: { ...VALID_REGISTRATION_RESPONSE.response, transports: [] },
          },
        });
        expect(insertDevice).toHaveBeenCalledWith(expect.objectContaining({ transports: null }));
      });

      it('stores deviceName when provided', async () => {
        await registerDevice({ deviceName: 'My Phone' });
        expect(insertDevice).toHaveBeenCalledWith(
          expect.objectContaining({ deviceName: 'My Phone' })
        );
      });

      it('stores null deviceName when omitted', async () => {
        await registerDevice();
        expect(insertDevice).toHaveBeenCalledWith(expect.objectContaining({ deviceName: null }));
      });

      it('stores signCount 0 when credential.counter is undefined', async () => {
        vi.mocked(verifyRegistrationResponse).mockResolvedValue({
          verified: true,
          registrationInfo: {
            credential: {
              id: VALID_CREDENTIAL_ID,
              publicKey: new Uint8Array([1, 2, 3]),
              counter: undefined,
            },
          },
        } as never);
        await registerDevice();
        expect(insertDevice).toHaveBeenCalledWith(expect.objectContaining({ signCount: 0 }));
      });

      it('returns 409 ATTESTATION_VERIFICATION_FAILED when credential_id is already registered', async () => {
        const uniqueViolation = Object.assign(new Error('duplicate key'), { code: '23505' });
        vi.mocked(insertDevice).mockRejectedValue(uniqueViolation);
        const res = await registerDevice();
        expect(res.statusCode).toBe(409);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ATTESTATION_VERIFICATION_FAILED });
      });

      it('rethrows unexpected DB errors from insertDevice', async () => {
        vi.mocked(insertDevice).mockRejectedValue(new Error('connection lost'));
        const res = await registerDevice();
        expect(res.statusCode).toBe(500);
      });
    });
  });

  describe('POST /api/auth/challenge', () => {
    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(generateAuthenticationOptions).mockResolvedValue({
          challenge: VALID_CHALLENGE,
        } as never);
        vi.mocked(insertLoginChallenge).mockResolvedValue(undefined);
      });

      it('returns 200 with WebAuthn authentication options', async () => {
        const res = await app.inject({ method: 'POST', url: CHALLENGE_URL });
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({ options: { challenge: VALID_CHALLENGE } });
      });

      it('stores the challenge via insertLoginChallenge', async () => {
        await app.inject({ method: 'POST', url: CHALLENGE_URL });
        expect(insertLoginChallenge).toHaveBeenCalledWith(VALID_CHALLENGE, expect.any(Date));
      });

      it('ignores any request body', async () => {
        const res = await app.inject({
          method: 'POST',
          url: CHALLENGE_URL,
          body: { unexpected: true },
        });
        expect(res.statusCode).toBe(200);
      });
    });
  });

  describe('POST /api/auth/login', () => {
    function login(body: Record<string, unknown> = { assertion: VALID_ASSERTION }) {
      return app.inject({ method: 'POST', url: LOGIN_URL, body });
    }

    describe('request validation', () => {
      it('returns 400 INVALID_INPUT when body is empty', async () => {
        const res = await app.inject({ method: 'POST', url: LOGIN_URL, body: {} });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when assertion is missing required fields', async () => {
        const res = await login({ assertion: { id: VALID_CREDENTIAL_ID } });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when assertion.type is not "public-key"', async () => {
        const res = await login({ assertion: { ...VALID_ASSERTION, type: 'other' } });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('device lookup', () => {
      it('returns 404 DEVICE_NOT_FOUND when getDeviceByCredentialId returns undefined', async () => {
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(undefined);
        const res = await login();
        expect(res.statusCode).toBe(404);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.DEVICE_NOT_FOUND });
      });

      it('returns 401 when device.sign_count exceeds Number.MAX_SAFE_INTEGER', async () => {
        const device = { ...makeDevice(), sign_count: BigInt(Number.MAX_SAFE_INTEGER) + 1n };
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(device as never);
        const res = await login();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ASSERTION_VERIFICATION_FAILED });
      });
    });

    describe('challenge extraction', () => {
      beforeEach(() => {
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(makeDevice() as never);
      });

      it('returns 400 INVALID_INPUT when extractChallenge throws', async () => {
        vi.mocked(extractChallenge).mockImplementation(() => {
          throw new Error('malformed');
        });
        const res = await login();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('challenge consumption', () => {
      beforeEach(() => {
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(makeDevice() as never);
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
      });

      it('returns 400 INVALID_OR_EXPIRED_CHALLENGE when consumeLoginChallenge returns false', async () => {
        vi.mocked(consumeLoginChallenge).mockResolvedValue(false);
        const res = await login();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_OR_EXPIRED_CHALLENGE });
      });
    });

    describe('WebAuthn assertion verification', () => {
      beforeEach(() => {
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(makeDevice() as never);
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
        vi.mocked(consumeLoginChallenge).mockResolvedValue(true);
      });

      it('returns 401 ASSERTION_VERIFICATION_FAILED when verifyAuthenticationResponse throws', async () => {
        vi.mocked(verifyAuthenticationResponse).mockRejectedValue(new Error('assertion error'));
        const res = await login();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ASSERTION_VERIFICATION_FAILED });
      });

      it('returns 401 ASSERTION_VERIFICATION_FAILED when verified is false', async () => {
        vi.mocked(verifyAuthenticationResponse).mockResolvedValue({ verified: false } as never);
        const res = await login();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ASSERTION_VERIFICATION_FAILED });
      });

      it('passes device transports when non-null to verifyAuthenticationResponse', async () => {
        vi.mocked(verifyAuthenticationResponse).mockResolvedValue(makeAuthVerification() as never);
        vi.mocked(incrementSignCountWithChallenge).mockResolvedValue(true);
        const device = { ...makeDevice(), transports: ['internal', 'hybrid'] };
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(device as never);
        await login();
        expect(verifyAuthenticationResponse).toHaveBeenCalledWith(
          expect.objectContaining({
            credential: expect.objectContaining({ transports: ['internal', 'hybrid'] }),
          })
        );
      });

      it('passes device sign_count as Number() to verifyAuthenticationResponse', async () => {
        vi.mocked(verifyAuthenticationResponse).mockResolvedValue(makeAuthVerification() as never);
        vi.mocked(incrementSignCountWithChallenge).mockResolvedValue(true);
        const device = { ...makeDevice(), sign_count: 42n };
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(device as never);
        await login();
        expect(verifyAuthenticationResponse).toHaveBeenCalledWith(
          expect.objectContaining({ credential: expect.objectContaining({ counter: 42 }) })
        );
      });
    });

    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(getDeviceByCredentialId).mockResolvedValue(makeDevice() as never);
        vi.mocked(extractChallenge).mockReturnValue(VALID_CHALLENGE);
        vi.mocked(consumeLoginChallenge).mockResolvedValue(true);
        vi.mocked(verifyAuthenticationResponse).mockResolvedValue(makeAuthVerification() as never);
        vi.mocked(incrementSignCountWithChallenge).mockResolvedValue(true);
      });

      it('returns 401 ASSERTION_VERIFICATION_FAILED when sign count guard blocks update', async () => {
        vi.mocked(incrementSignCountWithChallenge).mockResolvedValue(false);
        const res = await login();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.ASSERTION_VERIFICATION_FAILED });
      });

      it('advances sign count and inserts session challenge in a transaction', async () => {
        await login();
        expect(incrementSignCountWithChallenge).toHaveBeenCalledWith(
          VALID_DEVICE_ID,
          1,
          expect.any(String),
          expect.any(Date)
        );
      });

      it('returns 200 with sessionChallenge and deviceId', async () => {
        const res = await login();
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({ deviceId: VALID_DEVICE_ID });
        expect(typeof res.json().sessionChallenge).toBe('string');
      });

      it('sessionChallenge is a 32-byte base64url-encoded value', async () => {
        const res = await login();
        const { sessionChallenge } = res.json();
        expect(Buffer.from(sessionChallenge, 'base64url').length).toBe(32);
      });
    });
  });

  describe('POST /api/auth/session', () => {
    function postSession(
      body: Record<string, unknown> = { sessionBinding: VALID_SESSION_BINDING }
    ) {
      return app.inject({ method: 'POST', url: SESSION_URL, body });
    }

    describe('request validation', () => {
      it('returns 400 INVALID_INPUT when sessionBinding is missing', async () => {
        const res = await app.inject({ method: 'POST', url: SESSION_URL, body: {} });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when sessionBinding is shorter than MIN_SESSION_BINDING_LENGTH', async () => {
        const res = await postSession({ sessionBinding: SHORT_SESSION_BINDING });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when sessionBinding exceeds MAX_SESSION_BINDING_LENGTH', async () => {
        const res = await postSession({ sessionBinding: LONG_SESSION_BINDING });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('session binding verification', () => {
      it('returns 401 INVALID_SESSION_BINDING when verifySessionBindingJWS throws', async () => {
        vi.mocked(verifySessionBindingJWS).mockRejectedValue(new Error('invalid jws'));
        const res = await postSession();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_SESSION_BINDING });
      });
    });

    describe('session challenge consumption', () => {
      beforeEach(() => {
        vi.mocked(verifySessionBindingJWS).mockResolvedValue({
          sessionPublicKey: VALID_SESSION_PUBLIC_KEY,
          payload: { sessionChallenge: VALID_SESSION_CHALLENGE },
        } as never);
      });

      it('returns 400 INVALID_OR_EXPIRED_SESSION_CHALLENGE when consumeSessionChallenge returns undefined', async () => {
        vi.mocked(consumeSessionChallenge).mockResolvedValue(undefined);
        const res = await postSession();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({
          error: ERROR_CODES.INVALID_OR_EXPIRED_SESSION_CHALLENGE,
        });
      });

      it('returns 400 INVALID_OR_EXPIRED_SESSION_CHALLENGE when challenge has no device_id', async () => {
        vi.mocked(consumeSessionChallenge).mockResolvedValue({ device_id: '' } as never);
        const res = await postSession();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({
          error: ERROR_CODES.INVALID_OR_EXPIRED_SESSION_CHALLENGE,
        });
      });
    });

    describe('device lookup', () => {
      beforeEach(() => {
        vi.mocked(verifySessionBindingJWS).mockResolvedValue({
          sessionPublicKey: VALID_SESSION_PUBLIC_KEY,
          payload: { sessionChallenge: VALID_SESSION_CHALLENGE },
        } as never);
        vi.mocked(consumeSessionChallenge).mockResolvedValue({ device_id: VALID_DEVICE_ID });
      });

      it('returns 400 DEVICE_NOT_FOUND when getDeviceById returns undefined', async () => {
        vi.mocked(getDeviceById).mockResolvedValue(undefined);
        const res = await postSession();
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.DEVICE_NOT_FOUND });
      });
    });

    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(verifySessionBindingJWS).mockResolvedValue({
          sessionPublicKey: VALID_SESSION_PUBLIC_KEY,
          payload: { sessionChallenge: VALID_SESSION_CHALLENGE },
        } as never);
        vi.mocked(consumeSessionChallenge).mockResolvedValue({ device_id: VALID_DEVICE_ID });
        vi.mocked(getDeviceById).mockResolvedValue({
          user_id: VALID_USER_ID,
          credential_id: VALID_CREDENTIAL_ID,
        });
        vi.mocked(insertSession).mockResolvedValue(makeSession());
      });

      it('inserts session with sessionPublicKey from the verified JWS', async () => {
        await postSession();
        expect(insertSession).toHaveBeenCalledWith(
          expect.objectContaining({ sessionPublicKey: VALID_SESSION_PUBLIC_KEY })
        );
      });

      it('returns 200 with sessionId, expiresAt (unix ms), and userId', async () => {
        const session = makeSession();
        vi.mocked(insertSession).mockResolvedValue(session);
        const res = await postSession();
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({
          sessionId: session.id,
          expiresAt: session.expires_at.getTime(),
          userId: VALID_USER_ID,
        });
      });

      it('sets httpOnly SameSite=Lax session cookie with sessionId', async () => {
        const session = makeSession();
        vi.mocked(insertSession).mockResolvedValue(session);
        const res = await postSession();
        const raw = res.headers['set-cookie'];
        const cookieStr = Array.isArray(raw) ? raw[0] : (raw as string);
        expect(cookieStr).toContain(`ghostid_session=${session.id}`);
        expect(cookieStr).toContain('HttpOnly');
        expect(cookieStr).toContain('SameSite=Lax');
        expect(cookieStr).toContain('Path=/');
        expect(cookieStr).toContain('Max-Age=86400');
        expect(cookieStr).not.toContain('Secure');
      });

      it('sets SameSite=None and Secure when COOKIE_SECURE is true', async () => {
        const { config } = await import('../../config.js');
        const original = (config as Record<string, unknown>).COOKIE_SECURE;
        (config as Record<string, unknown>).COOKIE_SECURE = true;
        try {
          const session = makeSession();
          vi.mocked(insertSession).mockResolvedValue(session);
          const res = await postSession();
          const raw = res.headers['set-cookie'];
          const cookieStr = Array.isArray(raw) ? raw[0] : (raw as string);
          expect(cookieStr).toContain('SameSite=None');
          expect(cookieStr).toContain('Secure');
        } finally {
          (config as Record<string, unknown>).COOKIE_SECURE = original;
        }
      });
    });
  });

  describe('POST /api/auth/session/restore', () => {
    function postRestore(
      body: Record<string, unknown> = { sessionBinding: VALID_SESSION_BINDING },
      sessionCookie?: string
    ) {
      return app.inject({
        method: 'POST',
        url: SESSION_RESTORE_URL,
        body,
        cookies: sessionCookie !== undefined ? { ghostid_session: sessionCookie } : undefined,
      });
    }

    describe('request validation', () => {
      it('returns 401 SESSION_NOT_FOUND when session cookie is absent', async () => {
        const res = await postRestore();
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.SESSION_NOT_FOUND });
      });

      it('returns 401 SESSION_NOT_FOUND when session cookie is not a valid UUID', async () => {
        const res = await postRestore(undefined, 'not-a-uuid');
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.SESSION_NOT_FOUND });
      });

      it('returns 400 INVALID_INPUT when sessionBinding is missing', async () => {
        const res = await postRestore({}, VALID_SESSION_ID);
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when sessionBinding is shorter than MIN_SESSION_BINDING_LENGTH', async () => {
        const res = await postRestore({ sessionBinding: SHORT_SESSION_BINDING }, VALID_SESSION_ID);
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when sessionBinding exceeds MAX_SESSION_BINDING_LENGTH', async () => {
        const res = await postRestore({ sessionBinding: LONG_SESSION_BINDING }, VALID_SESSION_ID);
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('JWS verification', () => {
      it('returns 401 INVALID_SESSION_BINDING when verifySessionBindingJWS throws', async () => {
        vi.mocked(verifySessionBindingJWS).mockRejectedValue(new Error('bad jws'));
        const res = await postRestore(undefined, VALID_SESSION_ID);
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_SESSION_BINDING });
      });
    });

    describe('rebind failure', () => {
      beforeEach(() => {
        vi.mocked(verifySessionBindingJWS).mockResolvedValue({
          sessionPublicKey: VALID_SESSION_PUBLIC_KEY,
          payload: { sessionChallenge: 'random-nonce' },
        } as never);
      });

      it('returns 401 SESSION_NOT_FOUND when rebindSessionPublicKey returns undefined', async () => {
        vi.mocked(rebindSessionPublicKey).mockResolvedValue(undefined);
        const res = await postRestore(undefined, VALID_SESSION_ID);
        expect(res.statusCode).toBe(401);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.SESSION_NOT_FOUND });
      });

      it('clears the session cookie when rebind fails', async () => {
        vi.mocked(rebindSessionPublicKey).mockResolvedValue(undefined);
        const res = await postRestore(undefined, VALID_SESSION_ID);
        const raw = res.headers['set-cookie'];
        const cookieStr = Array.isArray(raw) ? raw[0] : (raw as string);
        expect(cookieStr).toMatch(/ghostid_session=;|ghostid_session=(?:;| |$)/);
      });
    });

    describe('success', () => {
      const REBIND_ROW = {
        user_id: VALID_USER_ID,
        device_id: VALID_DEVICE_ID,
        expires_at: new Date(Date.now() + 86_400_000),
      };

      beforeEach(() => {
        vi.mocked(verifySessionBindingJWS).mockResolvedValue({
          sessionPublicKey: VALID_SESSION_PUBLIC_KEY,
          payload: { sessionChallenge: 'random-nonce' },
        } as never);
        vi.mocked(rebindSessionPublicKey).mockResolvedValue(REBIND_ROW);
      });

      it('calls rebindSessionPublicKey with sessionId from cookie and new public key', async () => {
        await postRestore(undefined, VALID_SESSION_ID);
        expect(rebindSessionPublicKey).toHaveBeenCalledWith(
          VALID_SESSION_ID,
          VALID_SESSION_PUBLIC_KEY
        );
      });

      it('returns 200 with sessionId, userId, deviceId, and expiresAt', async () => {
        const res = await postRestore(undefined, VALID_SESSION_ID);
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({
          sessionId: VALID_SESSION_ID,
          userId: VALID_USER_ID,
          deviceId: VALID_DEVICE_ID,
          expiresAt: REBIND_ROW.expires_at.getTime(),
        });
      });
    });
  });

  describe('POST /api/auth/recover', () => {
    describe('request validation', () => {
      it('returns 400 INVALID_INPUT when body is empty', async () => {
        const res = await app.inject({ method: 'POST', url: RECOVER_URL, body: {} });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootPublicKey is too short', async () => {
        const res = await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: SHORT_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });

      it('returns 400 INVALID_INPUT when rootPublicKey is too long', async () => {
        const res = await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: LONG_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ error: ERROR_CODES.INVALID_INPUT });
      });
    });

    describe('unknown root public key', () => {
      beforeEach(() => {
        vi.mocked(getUserByRootPublicKey).mockResolvedValue(undefined);
        vi.mocked(buildRegistrationOptions).mockResolvedValue({
          challenge: VALID_CHALLENGE,
        } as never);
        vi.mocked(insertTimingRecoverChallenge).mockResolvedValue(undefined);
      });

      it('returns 200 with the same shape as a successful recover (no enumeration)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(200);
        const body = res.json();
        expect(Object.keys(body).sort()).toEqual(['options', 'userId'].sort());
        expect(typeof body.userId).toBe('string');
      });

      it('stores a timing challenge but not a real recover challenge when user does not exist', async () => {
        await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(insertRecoverChallenge).not.toHaveBeenCalled();
        expect(insertTimingRecoverChallenge).toHaveBeenCalledOnce();
      });
    });

    describe('happy path', () => {
      beforeEach(() => {
        vi.mocked(getUserByRootPublicKey).mockResolvedValue({ id: VALID_USER_ID });
        vi.mocked(buildRegistrationOptions).mockResolvedValue({
          challenge: VALID_CHALLENGE,
        } as never);
        vi.mocked(insertRecoverChallenge).mockResolvedValue(undefined);
      });

      it('returns 200 with userId and WebAuthn options for the existing user', async () => {
        const res = await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(res.statusCode).toBe(200);
        expect(res.json()).toMatchObject({
          userId: VALID_USER_ID,
          options: { challenge: VALID_CHALLENGE },
        });
      });

      it('inserts a recover challenge for the existing user', async () => {
        await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        expect(insertRecoverChallenge).toHaveBeenCalledWith(
          VALID_CHALLENGE,
          VALID_USER_ID,
          expect.any(Date)
        );
      });

      it('response shape matches /register response', async () => {
        const res = await app.inject({
          method: 'POST',
          url: RECOVER_URL,
          body: { rootPublicKey: VALID_ROOT_PUBLIC_KEY },
        });
        const body = res.json();
        expect(Object.keys(body).sort()).toEqual(['options', 'userId'].sort());
      });
    });
  });
});

import { sign as cryptoSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { canonicalJson } from '@ghostid/shared';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AUTH_HEADERS,
  ERROR_CODES,
  SESSION_AUTH_SCHEME,
  SESSION_SIG_TOLERANCE_SECONDS,
} from '../../constants';
import { storeNonce } from '../../db/queries/nonces.js';
import { getSessionWithUser, touchSession } from '../../db/queries/sessions.js';
import { registerSessionAuthPlugin, requireSession } from '../../plugins/session-auth.js';

vi.mock('../../db/queries/sessions.js', () => ({
  getSessionWithUser: vi.fn(),
  touchSession: vi.fn(),
}));

vi.mock('../../db/queries/nonces.js', () => ({
  storeNonce: vi.fn(),
}));

interface Keypair {
  privateKey: KeyObject;
  publicKeyB64: string;
}

const SESSION_ID = '550e8400-e29b-41d4-a716-446655440000';
const USER_ID = 'user-uuid-5678';
const DEVICE_ID = 'device-uuid-abcd';

function generateEd25519Keypair(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pubJwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, publicKeyB64: pubJwk.x };
}

const DEFAULT_PATH = '/api/devices';
const DEFAULT_METHOD = 'GET';

function makeSessionHeaders(
  sessionId: string,
  iat: number,
  privateKey: KeyObject,
  htu = DEFAULT_PATH,
  htm = DEFAULT_METHOD,
  jti = crypto.randomUUID()
) {
  const payload = canonicalJson({ htm, htu, iat, jti, sessionId });
  const sig = cryptoSign(null, Buffer.from(payload, 'utf-8'), privateKey).toString('base64url');
  return {
    [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${sessionId}`,
    [AUTH_HEADERS.SESSION_NONCE]: jti,
    [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
    [AUTH_HEADERS.SESSION_SIGNATURE]: sig,
  };
}

function makeSession(
  publicKeyB64: string,
  overrides: { expires_at?: Date; revoked_at?: Date | null } = {}
) {
  return {
    session_id: SESSION_ID,
    user_id: USER_ID,
    device_id: DEVICE_ID,
    session_public_key: publicKeyB64,
    expires_at: overrides.expires_at ?? new Date(Date.now() + 3_600_000),
    revoked_at: overrides.revoked_at ?? null,
  };
}

function makeMockReply() {
  const reply = { code: vi.fn(), send: vi.fn() };
  reply.code.mockReturnValue(reply);
  reply.send.mockReturnValue(reply);
  return reply;
}

function mockSessionRequest(
  headers: Record<string, string | string[] | undefined> = {},
  url = DEFAULT_PATH,
  method = DEFAULT_METHOD
) {
  return {
    headers,
    url,
    method,
    sessionContext: null,
    log: { error: vi.fn() },
  } as unknown as Parameters<typeof requireSession>[0];
}

let keypair: Keypair;
let otherKeypair: Keypair;

describe('session auth', () => {
  describe('registerSessionAuthPlugin', () => {
    it('calls app.decorateRequest with sessionContext and null', () => {
      const app = { decorateRequest: vi.fn() };
      registerSessionAuthPlugin(app as never);
      expect(app.decorateRequest).toHaveBeenCalledWith('sessionContext', null);
    });
  });

  describe('requireSession', () => {
    beforeAll(() => {
      keypair = generateEd25519Keypair();
      otherKeypair = generateEd25519Keypair();
    });

    beforeEach(() => {
      vi.mocked(getSessionWithUser).mockReset();
      vi.mocked(touchSession).mockReset();
      vi.mocked(touchSession).mockResolvedValue(undefined);
      vi.mocked(storeNonce).mockReset();
      vi.mocked(storeNonce).mockResolvedValue(true);
    });

    describe('header presence', () => {
      it('returns 401 MISSING_SESSION_HEADERS when all headers are absent', async () => {
        const reply = makeMockReply();
        await requireSession(mockSessionRequest({}), reply as never);
        expect(reply.code).toHaveBeenCalledWith(401);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });

      it('returns 401 MISSING_SESSION_HEADERS when authorization is missing', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });

      it('returns 401 MISSING_SESSION_HEADERS when x-ghostid-timestamp is missing', async () => {
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });

      it('returns 401 MISSING_SESSION_HEADERS when x-ghostid-signature is missing', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });

      it('returns 401 MISSING_SESSION_HEADERS when x-ghostid-nonce is missing', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });

      it('returns 401 MISSING_SESSION_HEADERS when a header is an array (multi-value)', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: [`${SESSION_AUTH_SCHEME} ${SESSION_ID}`, 'extra'],
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });
    });

    describe('authorization scheme', () => {
      it('returns 401 INVALID_AUTHORIZATION_SCHEME when scheme is Bearer instead of GhostID-Session', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `Bearer ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_AUTHORIZATION_SCHEME })
        );
      });

      it('returns 401 INVALID_AUTHORIZATION_SCHEME when authorization has no scheme prefix', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: SESSION_ID,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_AUTHORIZATION_SCHEME })
        );
      });

      it('returns 401 INVALID_AUTHORIZATION_SCHEME when scheme is correct but wrong case', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `ghostid-session ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_AUTHORIZATION_SCHEME })
        );
      });
    });

    describe('header parsing', () => {
      it('returns 401 MALFORMED_SESSION_HEADERS when sessionId is empty after extracting scheme', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} `,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MALFORMED_SESSION_HEADERS })
        );
      });

      it('returns 401 MALFORMED_SESSION_HEADERS when x-ghostid-timestamp is not a valid integer', async () => {
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: 'notanumber',
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MALFORMED_SESSION_HEADERS })
        );
      });

      it('returns 401 MALFORMED_SESSION_HEADERS when x-ghostid-timestamp is empty string', async () => {
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: '',
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MALFORMED_SESSION_HEADERS })
        );
      });

      it('returns 401 MALFORMED_SESSION_HEADERS when x-ghostid-nonce is not a valid UUID', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_NONCE]: 'not-a-uuid',
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MALFORMED_SESSION_HEADERS })
        );
      });

      it('returns 401 MALFORMED_SESSION_HEADERS when sessionId is not a valid UUID', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} not-a-uuid`,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: 'sig',
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MALFORMED_SESSION_HEADERS })
        );
      });
    });

    describe('timestamp tolerance', () => {
      it('returns 401 SESSION_TIMESTAMP_OUT_OF_RANGE when iat is more than tolerance seconds in the past', async () => {
        const iat = Math.floor(Date.now() / 1000) - SESSION_SIG_TOLERANCE_SECONDS - 1;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE })
        );
      });

      it('returns 401 SESSION_TIMESTAMP_OUT_OF_RANGE when iat is more than tolerance seconds in the future', async () => {
        const iat = Math.floor(Date.now() / 1000) + SESSION_SIG_TOLERANCE_SECONDS + 1;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE })
        );
      });

      it('passes timestamp check when iat is exactly tolerance seconds ago', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000) - SESSION_SIG_TOLERANCE_SECONDS;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });

      it('passes timestamp check when iat is exactly tolerance seconds in the future', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000) + SESSION_SIG_TOLERANCE_SECONDS;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });

      it('passes timestamp check when iat is current time', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });
    });

    describe('session lookup', () => {
      it('returns 401 SESSION_NOT_FOUND when getSessionWithUser returns undefined', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(getSessionWithUser).toHaveBeenCalledWith(SESSION_ID);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });
    });

    describe('session state', () => {
      it('returns 401 SESSION_NOT_FOUND when session is revoked or expired (filtered by SQL)', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });
    });

    describe('signature verification', () => {
      it('returns 401 INVALID_SESSION_SIGNATURE when signature is valid base64url but wrong bytes', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const wrongSig = Buffer.alloc(64).toString('base64url');
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_NONCE]: crypto.randomUUID(),
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
            [AUTH_HEADERS.SESSION_SIGNATURE]: wrongSig,
          }),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
      });

      it('returns 401 INVALID_SESSION_SIGNATURE when session_public_key is not a valid Ed25519 JWK x', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(
          makeSession('not-valid-base64url-key-x-value!!') as never
        );
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
      });

      it('returns 401 INVALID_SESSION_SIGNATURE when payload was signed with a different key', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, otherKeypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
      });

      it('passes and populates req.sessionContext when signature is valid', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const req = mockSessionRequest(headers);
        const reply = makeMockReply();
        await requireSession(req, reply as never);
        expect(reply.send).not.toHaveBeenCalled();
        expect(req.sessionContext).not.toBeNull();
      });

      it('returns 401 SESSION_REVOKED when the valid-signature session is revoked', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(
          makeSession(keypair.publicKeyB64, { revoked_at: new Date(Date.now() - 1000) }) as never
        );
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const req = mockSessionRequest(headers);
        const reply = makeMockReply();
        await requireSession(req, reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_REVOKED })
        );
        expect(req.sessionContext).toBeNull();
      });

      it('returns 401 SESSION_EXPIRED when the valid-signature session is past expiry', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(
          makeSession(keypair.publicKeyB64, { expires_at: new Date(Date.now() - 1000) }) as never
        );
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const req = mockSessionRequest(headers);
        const reply = makeMockReply();
        await requireSession(req, reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_EXPIRED })
        );
        expect(req.sessionContext).toBeNull();
      });

      it('reports invalid_signature (not revoked/expired) when a revoked session has a bad signature', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(
          makeSession(keypair.publicKeyB64, { revoked_at: new Date(Date.now() - 1000) }) as never
        );
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, otherKeypair.privateKey);
        const reply = makeMockReply();
        await requireSession(mockSessionRequest(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
      });
    });

    describe('nonce replay', () => {
      it('stores the jti with an expiry one tolerance window ahead', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const jti = crypto.randomUUID();
        const before = Date.now();
        await requireSession(
          mockSessionRequest(
            makeSessionHeaders(
              SESSION_ID,
              iat,
              keypair.privateKey,
              DEFAULT_PATH,
              DEFAULT_METHOD,
              jti
            )
          ),
          makeMockReply() as never
        );
        expect(storeNonce).toHaveBeenCalledWith(jti, expect.any(Date));
        const expiresAt = vi.mocked(storeNonce).mock.calls[0]?.[1] as Date;
        expect(expiresAt.getTime()).toBeGreaterThanOrEqual(
          before + SESSION_SIG_TOLERANCE_SECONDS * 1000
        );
        expect(expiresAt.getTime()).toBeLessThanOrEqual(
          Date.now() + SESSION_SIG_TOLERANCE_SECONDS * 1000
        );
      });

      it('returns 401 SESSION_NONCE_USED when the nonce store reports a replay', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        vi.mocked(storeNonce).mockResolvedValue(false);
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey)),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NONCE_USED })
        );
      });

      it('does not consume the nonce when the signature is invalid', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, otherKeypair.privateKey)),
          reply as never
        );
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
        expect(storeNonce).not.toHaveBeenCalled();
      });

      it('does not consume the nonce when the session is not found', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000);
        await requireSession(
          mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey)),
          makeMockReply() as never
        );
        expect(storeNonce).not.toHaveBeenCalled();
      });
    });

    describe('success', () => {
      it('sets req.sessionContext.sessionId to the extracted session ID', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const req = mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        expect(req.sessionContext?.sessionId).toBe(SESSION_ID);
      });

      it('sets req.sessionContext.userId from the session row', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const req = mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        expect(req.sessionContext?.userId).toBe(USER_ID);
      });

      it('sets req.sessionContext.deviceId from the session row', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const req = mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        expect(req.sessionContext?.deviceId).toBe(DEVICE_ID);
      });

      it('does not call reply.send() on success', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey)),
          reply as never
        );
        expect(reply.send).not.toHaveBeenCalled();
      });

      it('logs error when touchSession rejects', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        vi.mocked(touchSession).mockRejectedValue(new Error('db down'));
        const iat = Math.floor(Date.now() / 1000);
        const req = mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        // fire-and-forget: flush the microtask queue so the .catch runs
        await Promise.resolve();
        expect(req.log.error).toHaveBeenCalledWith(
          expect.objectContaining({ sessionId: SESSION_ID }),
          'touchSession failed'
        );
      });

      it('calls touchSession with the sessionId on success', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        await requireSession(
          mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey)),
          makeMockReply() as never
        );
        expect(touchSession).toHaveBeenCalledWith(SESSION_ID);
      });

      it('does not call touchSession when signature verification fails', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        await requireSession(
          mockSessionRequest(makeSessionHeaders(SESSION_ID, iat, otherKeypair.privateKey)),
          makeMockReply() as never
        );
        expect(touchSession).not.toHaveBeenCalled();
      });
    });
  });
});

import { sign as cryptoSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AUTH_HEADERS,
  ERROR_CODES,
  SESSION_AUTH_SCHEME,
  SESSION_SIG_TOLERANCE_SECONDS,
} from '../../constants';
import { getSessionWithUser, touchSession } from '../../db/queries/sessions.js';
import { registerSessionAuthPlugin, requireSession } from '../../plugins/session-auth.js';

vi.mock('../../db/queries/sessions.js', () => ({
  getSessionWithUser: vi.fn(),
  touchSession: vi.fn(),
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

function makeSessionHeaders(sessionId: string, iat: number, privateKey: KeyObject) {
  const payload = JSON.stringify({ sessionId, iat });
  const sig = cryptoSign(null, Buffer.from(payload, 'utf-8'), privateKey).toString('base64url');
  return {
    [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${sessionId}`,
    [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
    [AUTH_HEADERS.SESSION_SIGNATURE]: sig,
  };
}

function makeSession(publicKeyB64: string) {
  return {
    session_id: SESSION_ID,
    user_id: USER_ID,
    device_id: DEVICE_ID,
    session_public_key: publicKeyB64,
  };
}

function makeMockReply() {
  const reply = { code: vi.fn(), send: vi.fn() };
  reply.code.mockReturnValue(reply);
  reply.send.mockReturnValue(reply);
  return reply;
}

function makeReq(headers: Record<string, string | string[] | undefined> = {}) {
  return {
    headers,
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
    });

    describe('header presence', () => {
      it('returns 401 MISSING_SESSION_HEADERS when all three headers are absent', async () => {
        const reply = makeMockReply();
        await requireSession(makeReq({}), reply as never);
        expect(reply.code).toHaveBeenCalledWith(401);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.MISSING_SESSION_HEADERS })
        );
      });

      it('returns 401 MISSING_SESSION_HEADERS when authorization is missing', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          makeReq({
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
          makeReq({
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_TIMESTAMP]: String(iat),
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
          makeReq({
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `Bearer ${SESSION_ID}`,
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: SESSION_ID,
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `ghostid-session ${SESSION_ID}`,
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} `,
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
            [AUTH_HEADERS.SESSION_TIMESTAMP]: '',
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} not-a-uuid`,
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
        await requireSession(makeReq(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE })
        );
      });

      it('returns 401 SESSION_TIMESTAMP_OUT_OF_RANGE when iat is more than tolerance seconds in the future', async () => {
        const iat = Math.floor(Date.now() / 1000) + SESSION_SIG_TOLERANCE_SECONDS + 1;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(makeReq(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE })
        );
      });

      it('passes timestamp check when iat is exactly tolerance seconds ago', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000) - SESSION_SIG_TOLERANCE_SECONDS;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(makeReq(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });

      it('passes timestamp check when iat is exactly tolerance seconds in the future', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000) + SESSION_SIG_TOLERANCE_SECONDS;
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(makeReq(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.SESSION_NOT_FOUND })
        );
      });

      it('passes timestamp check when iat is current time', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(undefined as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const reply = makeMockReply();
        await requireSession(makeReq(headers), reply as never);
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
        await requireSession(makeReq(headers), reply as never);
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
        await requireSession(makeReq(headers), reply as never);
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
          makeReq({
            [AUTH_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${SESSION_ID}`,
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
        await requireSession(makeReq(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
      });

      it('returns 401 INVALID_SESSION_SIGNATURE when payload was signed with a different key', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, otherKeypair.privateKey);
        const reply = makeMockReply();
        await requireSession(makeReq(headers), reply as never);
        expect(reply.send).toHaveBeenCalledWith(
          expect.objectContaining({ error: ERROR_CODES.INVALID_SESSION_SIGNATURE })
        );
      });

      it('passes and populates req.sessionContext when signature is valid', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const headers = makeSessionHeaders(SESSION_ID, iat, keypair.privateKey);
        const req = makeReq(headers);
        const reply = makeMockReply();
        await requireSession(req, reply as never);
        expect(reply.send).not.toHaveBeenCalled();
        expect(req.sessionContext).not.toBeNull();
      });
    });

    describe('success', () => {
      it('sets req.sessionContext.sessionId to the extracted session ID', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const req = makeReq(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        expect(req.sessionContext?.sessionId).toBe(SESSION_ID);
      });

      it('sets req.sessionContext.userId from the session row', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const req = makeReq(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        expect(req.sessionContext?.userId).toBe(USER_ID);
      });

      it('sets req.sessionContext.deviceId from the session row', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const req = makeReq(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
        await requireSession(req, makeMockReply() as never);
        expect(req.sessionContext?.deviceId).toBe(DEVICE_ID);
      });

      it('does not call reply.send() on success', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        const reply = makeMockReply();
        await requireSession(
          makeReq(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey)),
          reply as never
        );
        expect(reply.send).not.toHaveBeenCalled();
      });

      it('logs error when touchSession rejects', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        vi.mocked(touchSession).mockRejectedValue(new Error('db down'));
        const iat = Math.floor(Date.now() / 1000);
        const req = makeReq(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey));
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
          makeReq(makeSessionHeaders(SESSION_ID, iat, keypair.privateKey)),
          makeMockReply() as never
        );
        expect(touchSession).toHaveBeenCalledWith(SESSION_ID);
      });

      it('does not call touchSession when signature verification fails', async () => {
        vi.mocked(getSessionWithUser).mockResolvedValue(makeSession(keypair.publicKeyB64) as never);
        const iat = Math.floor(Date.now() / 1000);
        await requireSession(
          makeReq(makeSessionHeaders(SESSION_ID, iat, otherKeypair.privateKey)),
          makeMockReply() as never
        );
        expect(touchSession).not.toHaveBeenCalled();
      });
    });
  });
});

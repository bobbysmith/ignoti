import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalJson } from '@ghostid/shared';
import type { FastifyBaseLogger, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AUTH_HEADERS,
  ERROR_CODES,
  SESSION_AUTH_SCHEME,
  SESSION_SIG_TOLERANCE_SECONDS,
  type ServerErrorCode,
} from '../constants.js';
import { getSessionWithUser, touchSession } from '../db/queries/sessions.js';
import { sendError } from '../helpers/response.js';

export interface SessionContext {
  sessionId: string;
  userId: string;
  deviceId: string;
}

/**
 * Raw session-auth material as received. Values are `unknown` because they
 * come either from HTTP headers (possibly string[] on duplicates) or from an
 * untyped JSON body on POST /api/sessions/verify.
 */
export interface SessionVerifyInput {
  authorization: unknown;
  nonce: unknown;
  timestamp: unknown;
  signature: unknown;
  method: string;
  path: string;
}

export type SessionVerifyResult =
  | { ok: true; context: SessionContext; expiresAt: Date }
  | { ok: false; code: ServerErrorCode };

declare module 'fastify' {
  interface FastifyRequest {
    sessionContext: SessionContext | null;
  }
}

// jti: expiry timestamp in millis. Entries evicted on the next insert after they expire.
const nonceCache = new Map<string, number>();
const uuidSchema = z.string().uuid();

function checkAndStoreNonce(jti: string): boolean {
  const now = Date.now();
  // Sweep expired entries before inserting to bound cache size
  for (const [key, exp] of nonceCache) {
    if (exp < now) {
      nonceCache.delete(key);
    }
  }
  if (nonceCache.has(jti)) return false;
  nonceCache.set(jti, now + SESSION_SIG_TOLERANCE_SECONDS * 1000);
  return true;
}

export function registerSessionAuthPlugin(app: FastifyInstance): void {
  app.decorateRequest('sessionContext', null);
}

/**
 * Verifies a per-request Ed25519 session signature and returns the session
 * context. Shared by `requireSession` (GhostID's own protected routes) and
 * POST /api/sessions/verify (integrator backends validating forwarded headers).
 *
 * Implements DPoP-style replay prevention (RFC 9449): the client signs
 * { htm, htu, iat, jti, sessionId } where `jti` is a per-request UUID.
 * The server rejects any `jti` it has seen within the tolerance window.
 */
export async function verifySessionAuth(
  input: SessionVerifyInput,
  log: FastifyBaseLogger
): Promise<SessionVerifyResult> {
  const { authorization, nonce, timestamp, signature } = input;

  if (
    typeof authorization !== 'string' ||
    typeof nonce !== 'string' ||
    typeof timestamp !== 'string' ||
    typeof signature !== 'string'
  ) {
    return { ok: false, code: ERROR_CODES.MISSING_SESSION_HEADERS };
  }

  if (!authorization.startsWith(`${SESSION_AUTH_SCHEME} `)) {
    return { ok: false, code: ERROR_CODES.INVALID_AUTHORIZATION_SCHEME };
  }

  const sessionId = authorization.slice(SESSION_AUTH_SCHEME.length + 1).trim();
  const jti = nonce.trim();
  const iat = parseInt(timestamp, 10);
  if (
    !sessionId ||
    !uuidSchema.safeParse(sessionId).success ||
    !jti ||
    !uuidSchema.safeParse(jti).success ||
    Number.isNaN(iat)
  ) {
    return { ok: false, code: ERROR_CODES.MALFORMED_SESSION_HEADERS };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - iat) > SESSION_SIG_TOLERANCE_SECONDS) {
    return { ok: false, code: ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE };
  }

  const session = await getSessionWithUser(sessionId);

  if (!session) {
    return { ok: false, code: ERROR_CODES.SESSION_NOT_FOUND };
  }

  const htu = input.path.split('?')[0];
  const htm = input.method.toUpperCase();
  const payload = canonicalJson({ htm, htu, iat, jti, sessionId });
  const data = Buffer.from(payload, 'utf-8');
  const sig = Buffer.from(signature, 'base64url');

  if (!checkAndStoreNonce(jti)) {
    return { ok: false, code: ERROR_CODES.SESSION_NONCE_USED };
  }

  let valid: boolean;
  try {
    const pubkey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: session.session_public_key },
      format: 'jwk',
    });
    valid = cryptoVerify(null, data, pubkey, sig);
  } catch {
    valid = false;
  }

  if (!valid) {
    return { ok: false, code: ERROR_CODES.INVALID_SESSION_SIGNATURE };
  }

  touchSession(sessionId).catch(err => {
    log.error({ err, sessionId }, 'touchSession failed');
  });

  return {
    ok: true,
    context: {
      sessionId,
      userId: session.user_id,
      deviceId: session.device_id,
    },
    expiresAt: session.expires_at,
  };
}

/**
 * Verifies the session signature on the incoming request and populates
 * `req.sessionContext`. Use as a `preHandler` on protected routes.
 */
export async function requireSession(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const result = await verifySessionAuth(
    {
      authorization: req.headers[AUTH_HEADERS.AUTHORIZATION],
      nonce: req.headers[AUTH_HEADERS.SESSION_NONCE],
      timestamp: req.headers[AUTH_HEADERS.SESSION_TIMESTAMP],
      signature: req.headers[AUTH_HEADERS.SESSION_SIGNATURE],
      method: req.method,
      path: req.url,
    },
    req.log
  );

  if (!result.ok) {
    return sendError(reply, 401, result.code);
  }

  req.sessionContext = result.context;
}

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalJson } from '@ghostid/shared';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AUTH_HEADERS,
  ERROR_CODES,
  SESSION_AUTH_SCHEME,
  SESSION_SIG_TOLERANCE_SECONDS,
} from '../constants.js';
import { getSessionWithUser, touchSession } from '../db/queries/sessions.js';
import { sendError } from '../helpers/response.js';

export interface SessionContext {
  sessionId: string;
  userId: string;
  deviceId: string;
}

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
 * Verifies a per-request Ed25519 session signature and populates
 * `req.sessionContext`. Use as a `preHandler` on protected routes.
 *
 * Implements DPoP-style replay prevention (RFC 9449): the client signs
 * { htm, htu, iat, jti, sessionId } where `jti` is a per-request UUID.
 * The server rejects any `jti` it has seen within the tolerance window.
 */
export async function requireSession(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const authHeader = req.headers[AUTH_HEADERS.AUTHORIZATION];
  const nonceHeader = req.headers[AUTH_HEADERS.SESSION_NONCE];
  const timestampHeader = req.headers[AUTH_HEADERS.SESSION_TIMESTAMP];
  const signatureHeader = req.headers[AUTH_HEADERS.SESSION_SIGNATURE];

  if (
    typeof authHeader !== 'string' ||
    typeof nonceHeader !== 'string' ||
    typeof timestampHeader !== 'string' ||
    typeof signatureHeader !== 'string'
  ) {
    return sendError(reply, 401, ERROR_CODES.MISSING_SESSION_HEADERS);
  }

  if (!authHeader.startsWith(`${SESSION_AUTH_SCHEME} `)) {
    return sendError(reply, 401, ERROR_CODES.INVALID_AUTHORIZATION_SCHEME);
  }

  const sessionId = authHeader.slice(SESSION_AUTH_SCHEME.length + 1).trim();
  const jti = nonceHeader.trim();
  const iat = parseInt(timestampHeader, 10);
  if (
    !sessionId ||
    !uuidSchema.safeParse(sessionId).success ||
    !jti ||
    !uuidSchema.safeParse(jti).success ||
    Number.isNaN(iat)
  ) {
    return sendError(reply, 401, ERROR_CODES.MALFORMED_SESSION_HEADERS);
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - iat) > SESSION_SIG_TOLERANCE_SECONDS) {
    return sendError(reply, 401, ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE);
  }

  const session = await getSessionWithUser(sessionId);

  if (!session) {
    return sendError(reply, 401, ERROR_CODES.SESSION_NOT_FOUND);
  }

  const htu = req.url.split('?')[0];
  const htm = req.method.toUpperCase();
  const payload = canonicalJson({ htm, htu, iat, jti, sessionId });
  const data = Buffer.from(payload, 'utf-8');
  const sig = Buffer.from(signatureHeader, 'base64url');

  if (!checkAndStoreNonce(jti)) {
    return sendError(reply, 401, ERROR_CODES.SESSION_NONCE_USED);
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
    return sendError(reply, 401, ERROR_CODES.INVALID_SESSION_SIGNATURE);
  }

  req.sessionContext = {
    sessionId,
    userId: session.user_id,
    deviceId: session.device_id,
  };

  touchSession(sessionId).catch(err => {
    req.log.error({ err, sessionId }, 'touchSession failed');
  });
}

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
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

export function registerSessionAuthPlugin(app: FastifyInstance): void {
  app.decorateRequest('sessionContext', null);
}

/**
 * Verifies a per-request Ed25519 session signature and populates
 * `req.sessionContext`. Use as a `preHandler` on protected routes.
 *
 * The client signs `JSON.stringify({ sessionId, iat })` with the session
 * private key. Key insertion order must match `sessionId` before `iat`,
 * which is guaranteed when both sides construct the literal in that order.
 */
export async function requireSession(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const authHeader = req.headers[AUTH_HEADERS.AUTHORIZATION];
  const timestampHeader = req.headers[AUTH_HEADERS.SESSION_TIMESTAMP];
  const signatureHeader = req.headers[AUTH_HEADERS.SESSION_SIGNATURE];

  if (
    typeof authHeader !== 'string' ||
    typeof timestampHeader !== 'string' ||
    typeof signatureHeader !== 'string'
  ) {
    return sendError(reply, 401, ERROR_CODES.MISSING_SESSION_HEADERS);
  }

  if (!authHeader.startsWith(`${SESSION_AUTH_SCHEME} `)) {
    return sendError(reply, 401, ERROR_CODES.INVALID_AUTHORIZATION_SCHEME);
  }

  const sessionId = authHeader.slice(SESSION_AUTH_SCHEME.length + 1).trim();
  const iat = parseInt(timestampHeader, 10);

  if (!sessionId || Number.isNaN(iat)) {
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
  if (session.revoked_at !== null) {
    return sendError(reply, 401, ERROR_CODES.SESSION_REVOKED);
  }
  if (session.expires_at < new Date()) {
    return sendError(reply, 401, ERROR_CODES.SESSION_EXPIRED);
  }

  const payload = JSON.stringify({ sessionId, iat });
  const data = Buffer.from(payload, 'utf-8');
  const sig = Buffer.from(signatureHeader, 'base64url');

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

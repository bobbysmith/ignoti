import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { config } from '../config.js';
import { ERROR_CODES } from '../constants.js';
import { sendError } from '../helpers/response.js';

const BEARER_RE = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/i;

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

/**
 * Returns an onRequest hook that rejects callers without a valid
 * `Authorization: Bearer <INTROSPECTION_SECRET>` header.
 * Throws when INTROSPECTION_SECRET is not configured.
 */
export function createIntrospectionAuth(): (
  req: FastifyRequest,
  reply: FastifyReply
) => Promise<unknown> {
  if (!config.INTROSPECTION_SECRET) {
    throw new Error('INTROSPECTION_SECRET is required');
  }
  const accepted = [config.INTROSPECTION_SECRET, config.INTROSPECTION_SECRET_PREVIOUS]
    .filter((s): s is string => typeof s === 'string')
    .map(digest);

  return async (req, reply) => {
    const match = BEARER_RE.exec(req.headers.authorization ?? '');
    const presented = digest(match?.[1] ?? '');
    let valid = false;
    for (const candidate of accepted) {
      // No early exit: timing must not depend on which secret matched.
      if (timingSafeEqual(presented, candidate)) valid = true;
    }
    if (!match || !valid) {
      reply.header('WWW-Authenticate', 'Bearer');
      return sendError(reply, 401, ERROR_CODES.INVALID_INTROSPECTION_CREDENTIALS);
    }
  };
}

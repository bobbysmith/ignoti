import type { ServerErrorResponse } from '@ignoti/shared';
import type { FastifyError, FastifyInstance, FastifyReply } from 'fastify';
import { ERROR_CODES, ERROR_MESSAGES, type ServerErrorCode } from '../constants.js';
import { errDetail } from '../lib/logging.js';

/**
 * Sends a consistent error envelope: { error, message, details? }.
 * `details` is included only for validation errors (invalid_input).
 */
export function sendError(
  reply: FastifyReply,
  status: number,
  code: ServerErrorCode,
  details?: unknown
): ReturnType<FastifyReply['send']> {
  const body: ServerErrorResponse = { error: code, message: ERROR_MESSAGES[code] };
  if (details !== undefined) body.details = details;
  return reply.code(status).send(body);
}

/**
 * 4xx errors keep Fastify's default response. Everything else is logged and
 * answered with a generic 500.
 */
export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((error: FastifyError, req, reply) => {
    const status = error.statusCode;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      return reply.code(status).send(error);
    }
    req.log.error({ reason: errDetail(error) }, 'unhandled error');
    return sendError(reply, 500, ERROR_CODES.INTERNAL_ERROR);
  });
}

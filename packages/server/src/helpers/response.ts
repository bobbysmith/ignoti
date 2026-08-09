import type { ServerErrorResponse } from '@ignoti/shared';
import type { FastifyReply } from 'fastify';
import { ERROR_MESSAGES, type ServerErrorCode } from '../constants.js';

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

import type { FastifyReply } from 'fastify';

import { config } from '../config.js';
import { SESSION_COOKIE_NAME } from '../constants.js';

function baseOptions() {
  const secure = config.COOKIE_SECURE;
  return {
    httpOnly: true,
    secure,
    sameSite: secure ? ('none' as const) : ('lax' as const),
    path: '/',
  };
}

export function setSessionCookie(reply: FastifyReply, value: string): void {
  reply.setCookie(SESSION_COOKIE_NAME, value, {
    ...baseOptions(),
    maxAge: config.SESSION_TTL_SECONDS,
  });
}

// Must carry the attributes the cookie was set with, or cross-site responses
// do not clear it.
export function clearSessionCookie(reply: FastifyReply): void {
  reply.clearCookie(SESSION_COOKIE_NAME, baseOptions());
}

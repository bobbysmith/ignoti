import { createHash, randomBytes } from 'node:crypto';

/**
 * Rotating restore secret for the session cookie. The cookie carries
 * `${sessionId}.${secret}`; the server stores only `hash` and rotates the
 * secret on every successful restore (RFC 9700 refresh-token rotation).
 */
export function generateRestoreToken(): { secret: string; hash: string } {
  const secret = randomBytes(32).toString('base64url');
  return { secret, hash: hashRestoreToken(secret) };
}

export function hashRestoreToken(secret: string): string {
  return createHash('sha256').update(secret).digest('base64url');
}

// Cookie value format: `${sessionId}.${secret}`.
export function buildSessionCookie(sessionId: string, secret: string): string {
  return `${sessionId}.${secret}`;
}

// Splits `${sessionId}.${secret}`; returns null if malformed.
export function parseSessionCookie(value: string): { sessionId: string; secret: string } | null {
  const dot = value.indexOf('.');
  if (dot < 1 || dot === value.length - 1) {
    return null;
  }
  return { sessionId: value.slice(0, dot), secret: value.slice(dot + 1) };
}

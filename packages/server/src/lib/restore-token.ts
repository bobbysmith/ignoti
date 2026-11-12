import { createHash, randomBytes } from 'node:crypto';

/**
 * Restore secrets for the session cookie. The cookie carries
 * `${sessionId}.${family}.${secret}`:
 *
 *   - `secret` rotates on every successful restore (RFC 9700 refresh-token
 *     rotation); only the current one restores the session.
 *   - `family` is minted once at login and never changes for the life of the
 *     session, so every cookie ever issued for the session carries it.
 *
 * The server stores only the SHA-256 hash of each. A matching family with a
 * non-current secret is an earlier cookie being replayed and revokes the session.
 */
export function generateRestoreToken(): { secret: string; hash: string } {
  const secret = randomBytes(32).toString('base64url');
  return { secret, hash: hashRestoreToken(secret) };
}

export function hashRestoreToken(secret: string): string {
  return createHash('sha256').update(secret).digest('base64url');
}

// Cookie value format: `${sessionId}.${family}.${secret}`.
export function buildSessionCookie(sessionId: string, family: string, secret: string): string {
  return `${sessionId}.${family}.${secret}`;
}

// Splits `${sessionId}.${family}.${secret}`; returns null if malformed.
export function parseSessionCookie(
  value: string
): { sessionId: string; family: string; secret: string } | null {
  const parts = value.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [sessionId, family, secret] = parts as [string, string, string];
  if (!sessionId || !family || !secret) {
    return null;
  }
  return { sessionId, family, secret };
}

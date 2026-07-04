import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  buildSessionCookie,
  generateRestoreToken,
  hashRestoreToken,
  parseSessionCookie,
} from '../../lib/restore-token.js';

describe('restore-token', () => {
  describe('generateRestoreToken', () => {
    it('returns a base64url secret and its SHA-256 hash', () => {
      const { secret, hash } = generateRestoreToken();
      expect(secret).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(hash).toBe(createHash('sha256').update(secret).digest('base64url'));
    });

    it('produces a distinct secret each call', () => {
      const a = generateRestoreToken();
      const b = generateRestoreToken();
      expect(a.secret).not.toBe(b.secret);
      expect(a.hash).not.toBe(b.hash);
    });
  });

  describe('hashRestoreToken', () => {
    it('is deterministic for the same secret', () => {
      expect(hashRestoreToken('abc')).toBe(hashRestoreToken('abc'));
    });

    it('differs for different secrets', () => {
      expect(hashRestoreToken('abc')).not.toBe(hashRestoreToken('abd'));
    });
  });

  describe('buildSessionCookie / parseSessionCookie', () => {
    const sessionId = '550e8400-e29b-41d4-a716-446655440001';
    const secret = 'cmVzdG9yZS1zZWNyZXQ';

    it('round-trips a session id and secret', () => {
      const cookie = buildSessionCookie(sessionId, secret);
      expect(parseSessionCookie(cookie)).toEqual({ sessionId, secret });
    });

    it('returns null for a bare session id (old format, no secret)', () => {
      expect(parseSessionCookie(sessionId)).toBeNull();
    });

    it('returns null when the secret is empty', () => {
      expect(parseSessionCookie(`${sessionId}.`)).toBeNull();
    });

    it('returns null when there is no session id before the dot', () => {
      expect(parseSessionCookie(`.${secret}`)).toBeNull();
    });

    it('keeps a secret that itself contains dots intact', () => {
      const dotted = 'a.b.c';
      expect(parseSessionCookie(`${sessionId}.${dotted}`)).toEqual({
        sessionId,
        secret: dotted,
      });
    });
  });
});

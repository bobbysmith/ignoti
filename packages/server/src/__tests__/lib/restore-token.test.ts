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
    const family = 'ZmFtaWx5LXNlY3JldA';
    const secret = 'cmVzdG9yZS1zZWNyZXQ';

    it('round-trips a session id, family, and secret', () => {
      const cookie = buildSessionCookie(sessionId, family, secret);
      expect(parseSessionCookie(cookie)).toEqual({ sessionId, family, secret });
    });

    it('returns null for a bare session id (oldest format)', () => {
      expect(parseSessionCookie(sessionId)).toBeNull();
    });

    it('returns null for the previous two-part format (no family)', () => {
      expect(parseSessionCookie(`${sessionId}.${secret}`)).toBeNull();
    });

    it('returns null when any part is empty', () => {
      expect(parseSessionCookie(`.${family}.${secret}`)).toBeNull();
      expect(parseSessionCookie(`${sessionId}..${secret}`)).toBeNull();
      expect(parseSessionCookie(`${sessionId}.${family}.`)).toBeNull();
    });

    it('returns null when there are more than three parts', () => {
      expect(parseSessionCookie(`${sessionId}.${family}.${secret}.extra`)).toBeNull();
    });
  });
});

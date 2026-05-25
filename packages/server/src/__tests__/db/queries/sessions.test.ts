import { beforeEach, describe, expect, it, vi } from 'vitest';
import { sql } from '../../../db/client.js';
import {
  getSessionsForUser,
  getSessionWithUser,
  insertSession,
  rebindSessionPublicKey,
  revokeAllSessionsForUser,
  revokeSessionForUser,
  touchSession,
} from '../../../db/queries/sessions.js';

vi.mock('../../../db/client.js', () => ({ sql: vi.fn() }));

const SESSION_ID = 'session-uuid-1234';
const DEVICE_ID = 'device-uuid-abcd';
const USER_ID = 'user-uuid-5678';
const SESSION_PUBLIC_KEY = 'session-pub-key-b64';

describe('sessions db queries', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('insertSession', () => {
    const params = {
      deviceId: DEVICE_ID,
      sessionPublicKey: SESSION_PUBLIC_KEY,
      expiresAt: new Date('2026-12-01T00:00:00Z'),
    };

    it('returns { id, expires_at } when INSERT succeeds', async () => {
      const row = { id: SESSION_ID, expires_at: params.expiresAt };
      vi.mocked(sql).mockResolvedValueOnce([row] as never);
      await expect(insertSession(params)).resolves.toEqual(row);
    });

    it('throws "insertSession returned no row" when INSERT returns empty array', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(insertSession(params)).rejects.toThrow('insertSession returned no row');
    });

    it('executes INSERT with deviceId, sessionPublicKey, and expiresAt', async () => {
      vi.mocked(sql).mockResolvedValueOnce([
        { id: SESSION_ID, expires_at: params.expiresAt },
      ] as never);
      await insertSession(params);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(
        expect.arrayContaining([DEVICE_ID, SESSION_PUBLIC_KEY, params.expiresAt])
      );
    });
  });

  describe('getSessionWithUser', () => {
    const activeRow = {
      session_public_key: SESSION_PUBLIC_KEY,
      device_id: DEVICE_ID,
      user_id: USER_ID,
    };

    it('returns the SessionAuthRow when session exists and device is joined', async () => {
      vi.mocked(sql).mockResolvedValueOnce([activeRow] as never);
      await expect(getSessionWithUser(SESSION_ID)).resolves.toEqual(activeRow);
    });

    it('returns undefined when sessionId is not found', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getSessionWithUser(SESSION_ID)).resolves.toBeUndefined();
    });

    it('returns undefined when the device associated with the session is deleted (join returns nothing)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getSessionWithUser(SESSION_ID)).resolves.toBeUndefined();
    });

    it('query filters out revoked sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getSessionWithUser(SESSION_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });

    it('query filters out expired sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getSessionWithUser(SESSION_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('expires_at > now()');
    });

    it('passes sessionId to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getSessionWithUser(SESSION_ID);
      expect(vi.mocked(sql).mock.calls[0]).toContain(SESSION_ID);
    });
  });

  describe('touchSession', () => {
    it('executes UPDATE with the sessionId', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await touchSession(SESSION_ID);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([SESSION_ID]));
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(touchSession(SESSION_ID)).resolves.toBeUndefined();
    });
  });

  describe('getSessionsForUser', () => {
    const row = {
      id: SESSION_ID,
      device_id: DEVICE_ID,
      created_at: new Date('2024-01-01T00:00:00Z'),
      last_used_at: null,
      expires_at: new Date('2024-01-08T00:00:00Z'),
    };

    it('returns active sessions for the user', async () => {
      vi.mocked(sql).mockResolvedValueOnce([row] as never);
      await expect(getSessionsForUser(USER_ID)).resolves.toEqual([row]);
    });

    it('returns empty array when user has no active sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getSessionsForUser(USER_ID)).resolves.toEqual([]);
    });

    it('query filters by revoked_at is null', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getSessionsForUser(USER_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });

    it('query filters by expires_at > now()', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getSessionsForUser(USER_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('expires_at > now()');
    });

    it('passes userId to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getSessionsForUser(USER_ID);
      expect(vi.mocked(sql).mock.calls[0]).toContain(USER_ID);
    });
  });

  describe('rebindSessionPublicKey', () => {
    const NEW_PUBLIC_KEY = 'new-session-pub-key-b64';
    const expiresAt = new Date('2026-12-01T00:00:00Z');
    const rebindRow = { user_id: USER_ID, device_id: DEVICE_ID, expires_at: expiresAt };

    it('returns the rebind row when session is active and not revoked', async () => {
      vi.mocked(sql).mockResolvedValueOnce([rebindRow] as never);
      await expect(rebindSessionPublicKey(SESSION_ID, NEW_PUBLIC_KEY)).resolves.toEqual(rebindRow);
    });

    it('returns undefined when session is not found, revoked, or expired', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(rebindSessionPublicKey(SESSION_ID, NEW_PUBLIC_KEY)).resolves.toBeUndefined();
    });

    it('passes sessionId and newPublicKey to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([rebindRow] as never);
      await rebindSessionPublicKey(SESSION_ID, NEW_PUBLIC_KEY);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([SESSION_ID, NEW_PUBLIC_KEY]));
    });

    it('query guards against revoked sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await rebindSessionPublicKey(SESSION_ID, NEW_PUBLIC_KEY);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });

    it('query guards against expired sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await rebindSessionPublicKey(SESSION_ID, NEW_PUBLIC_KEY);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('expires_at > now()');
    });
  });

  describe('revokeSessionForUser', () => {
    it('returns true when the session is revoked', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: SESSION_ID }] as never);
      await expect(revokeSessionForUser(SESSION_ID, USER_ID)).resolves.toBe(true);
    });

    it('returns false when the session is not found or not owned', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(revokeSessionForUser(SESSION_ID, USER_ID)).resolves.toBe(false);
    });

    it('passes sessionId and userId to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: SESSION_ID }] as never);
      await revokeSessionForUser(SESSION_ID, USER_ID);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([SESSION_ID, USER_ID]));
    });

    it('query includes revoked_at is null guard', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await revokeSessionForUser(SESSION_ID, USER_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });
  });

  describe('revokeAllSessionsForUser', () => {
    it('returns the number of sessions revoked', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: 's1' }, { id: 's2' }, { id: 's3' }] as never);
      await expect(revokeAllSessionsForUser(USER_ID)).resolves.toBe(3);
    });

    it('returns 0 when the user has no active sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(revokeAllSessionsForUser(USER_ID)).resolves.toBe(0);
    });

    it('passes userId to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await revokeAllSessionsForUser(USER_ID);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([USER_ID]));
    });

    it('query scopes to devices the user owns', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await revokeAllSessionsForUser(USER_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      const joined = query.join('');
      expect(joined).toContain('revoked_at is null');
      expect(joined).toContain('select id from devices');
    });
  });
});

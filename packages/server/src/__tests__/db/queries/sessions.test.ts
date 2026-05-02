import { beforeEach, describe, expect, it, vi } from 'vitest';

import { sql } from '../../../db/client.js';
import {
  getSessionWithUser,
  insertSession,
  revokeSessionsByDevice,
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
      expires_at: new Date('2026-12-01T00:00:00Z'),
      revoked_at: null,
      device_id: DEVICE_ID,
      user_id: USER_ID,
    };

    it('returns the full SessionAuthRow when session exists and device is joined', async () => {
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

    it('returns session with revoked_at = null when session is active', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ ...activeRow, revoked_at: null }] as never);
      const result = await getSessionWithUser(SESSION_ID);
      expect(result?.revoked_at).toBeNull();
    });

    it('returns session with revoked_at set when session is revoked (no filtering in this query)', async () => {
      const revokedAt = new Date('2026-06-01T00:00:00Z');
      vi.mocked(sql).mockResolvedValueOnce([{ ...activeRow, revoked_at: revokedAt }] as never);
      const result = await getSessionWithUser(SESSION_ID);
      expect(result?.revoked_at).toEqual(revokedAt);
    });

    it('returns session with expires_at in past (no filtering; caller checks expiry)', async () => {
      const pastExpiry = new Date('2020-01-01T00:00:00Z');
      vi.mocked(sql).mockResolvedValueOnce([{ ...activeRow, expires_at: pastExpiry }] as never);
      const result = await getSessionWithUser(SESSION_ID);
      expect(result?.expires_at).toEqual(pastExpiry);
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

  describe('revokeSessionsByDevice', () => {
    it('executes UPDATE passing deviceId', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await revokeSessionsByDevice(DEVICE_ID);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([DEVICE_ID]));
    });

    it('query only revokes where revoked_at is null', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await revokeSessionsByDevice(DEVICE_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(revokeSessionsByDevice(DEVICE_ID)).resolves.toBeUndefined();
    });

    it('resolves to void (no error) when device has no active sessions', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(revokeSessionsByDevice(DEVICE_ID)).resolves.toBeUndefined();
    });

    it('resolves to void (no error) when deviceId is not found', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(revokeSessionsByDevice('nonexistent')).resolves.toBeUndefined();
    });
  });
});

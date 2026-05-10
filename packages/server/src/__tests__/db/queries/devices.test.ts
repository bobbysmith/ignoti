import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import { sql } from '../../../db/client.js';
import {
  getDeviceByCredentialId,
  getDeviceById,
  getDevicesForUser,
  insertDevice,
  revokeDeviceWithSessions,
} from '../../../db/queries/devices.js';

vi.mock('../../../db/client.js', () => {
  const sqlFn = vi.fn();
  Object.assign(sqlFn, { begin: vi.fn() });
  return { sql: sqlFn };
});

const DEVICE_ID = 'device-uuid-abcd';
const USER_ID = 'user-uuid-1234';
const CREDENTIAL_ID = 'cred-id-base64url';
const PASSKEY_PUBLIC_KEY = 'passkey-pub-b64';
const DEVICE_NAME = 'My Phone';

describe('devices db queries', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('getDevicesForUser', () => {
    it('returns all non-revoked devices for userId', async () => {
      const rows = [
        {
          id: DEVICE_ID,
          credential_id: CREDENTIAL_ID,
          device_name: DEVICE_NAME,
          created_at: new Date(),
          last_used_at: null,
        },
      ];
      vi.mocked(sql).mockResolvedValueOnce(rows as never);
      await expect(getDevicesForUser(USER_ID)).resolves.toEqual(rows);
    });

    it('returns empty array when user has no devices', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getDevicesForUser(USER_ID)).resolves.toEqual([]);
    });

    it('excludes devices where revoked_at is not null', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getDevicesForUser(USER_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });

    it('includes devices where last_used_at is null', async () => {
      const rows = [
        {
          id: DEVICE_ID,
          credential_id: CREDENTIAL_ID,
          device_name: null,
          created_at: new Date(),
          last_used_at: null,
        },
      ];
      vi.mocked(sql).mockResolvedValueOnce(rows as never);
      const result = await getDevicesForUser(USER_ID);
      expect(result[0].last_used_at).toBeNull();
    });
  });

  describe('getDeviceByCredentialId', () => {
    it('returns the device row when a non-revoked device matches credentialId', async () => {
      const row = {
        id: DEVICE_ID,
        credential_id: CREDENTIAL_ID,
        passkey_public_key: PASSKEY_PUBLIC_KEY,
        sign_count: '0',
        transports: null,
      };
      vi.mocked(sql).mockResolvedValueOnce([row] as never);
      await expect(getDeviceByCredentialId(CREDENTIAL_ID)).resolves.toEqual(row);
    });

    it('returns undefined when no device matches credentialId', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getDeviceByCredentialId(CREDENTIAL_ID)).resolves.toBeUndefined();
    });

    it('returns undefined when the matching device is revoked', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getDeviceByCredentialId(CREDENTIAL_ID)).resolves.toBeUndefined();
    });
  });

  describe('getDeviceById', () => {
    it('returns { user_id, credential_id } for a non-revoked device', async () => {
      const row = { user_id: USER_ID, credential_id: CREDENTIAL_ID };
      vi.mocked(sql).mockResolvedValueOnce([row] as never);
      await expect(getDeviceById(DEVICE_ID)).resolves.toEqual(row);
    });

    it('returns undefined when no device matches id', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getDeviceById(DEVICE_ID)).resolves.toBeUndefined();
    });

    it('returns undefined when the matching device is revoked (revoked_at is not null)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getDeviceById(DEVICE_ID)).resolves.toBeUndefined();
    });

    it('query filters revoked_at is null', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await getDeviceById(DEVICE_ID);
      const query = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(query.join('')).toContain('revoked_at is null');
    });
  });

  describe('insertDevice', () => {
    const params = {
      userId: USER_ID,
      credentialId: CREDENTIAL_ID,
      passkeyPublicKey: PASSKEY_PUBLIC_KEY,
      signCount: 0,
      transports: null,
      deviceName: null,
    };

    it('executes INSERT with all provided params and returns { id }', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      await expect(insertDevice(params)).resolves.toEqual({ id: DEVICE_ID });
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([USER_ID, CREDENTIAL_ID, PASSKEY_PUBLIC_KEY, 0]));
    });

    it('stores transports as null when passed as null', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      await insertDevice({ ...params, transports: null });
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([null]));
    });

    it('stores transports array when passed as an array', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      const transports = ['internal', 'hybrid'];
      await insertDevice({ ...params, transports });
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([transports]));
    });

    it('stores deviceName as null when passed as null', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      await insertDevice({ ...params, deviceName: null });
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([null]));
    });

    it('throws "insertDevice returned no row" when INSERT returns empty array', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(insertDevice(params)).rejects.toThrow('insertDevice returned no row');
    });
  });

  describe('revokeDeviceWithSessions', () => {
    const sqlWithBegin = sql as unknown as Mock & { begin: Mock };

    beforeEach(() => {
      sqlWithBegin.begin = vi.fn(async (fn: (tx: Mock) => Promise<void>) =>
        fn(sql as unknown as Mock)
      );
    });

    it('wraps both updates in a transaction', async () => {
      vi.mocked(sql).mockResolvedValue([] as never);
      await revokeDeviceWithSessions(DEVICE_ID);
      expect(sqlWithBegin.begin).toHaveBeenCalledOnce();
    });

    it('revokes the device row with revoked_at guard', async () => {
      vi.mocked(sql).mockResolvedValue([] as never);
      await revokeDeviceWithSessions(DEVICE_ID);
      const firstQuery = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(firstQuery.join('')).toContain('update devices');
      expect(firstQuery.join('')).toContain('revoked_at is null');
    });

    it('revokes associated sessions with revoked_at guard', async () => {
      vi.mocked(sql).mockResolvedValue([] as never);
      await revokeDeviceWithSessions(DEVICE_ID);
      const secondQuery = vi.mocked(sql).mock.calls[1][0] as readonly string[];
      expect(secondQuery.join('')).toContain('update sessions');
      expect(secondQuery.join('')).toContain('revoked_at is null');
    });

    it('passes deviceId to both queries', async () => {
      vi.mocked(sql).mockResolvedValue([] as never);
      await revokeDeviceWithSessions(DEVICE_ID);
      expect(vi.mocked(sql).mock.calls[0]).toContain(DEVICE_ID);
      expect(vi.mocked(sql).mock.calls[1]).toContain(DEVICE_ID);
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValue([] as never);
      await expect(revokeDeviceWithSessions(DEVICE_ID)).resolves.toBeUndefined();
    });
  });
});

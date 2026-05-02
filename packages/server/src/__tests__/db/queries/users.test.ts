import { beforeEach, describe, expect, it, vi } from 'vitest';

import { sql } from '../../../db/client.js';
import { getUserById, getUserByRootPublicKey, upsertUser } from '../../../db/queries/users.js';

vi.mock('../../../db/client.js', () => ({ sql: vi.fn() }));

const USER_ID = 'user-uuid-1234';
const ROOT_PUBLIC_KEY = 'root-pub-key-b64url';

describe('users db queries', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('upsertUser', () => {
    it('returns { id } when INSERT succeeds (new user)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: USER_ID }] as never);
      await expect(upsertUser(ROOT_PUBLIC_KEY)).resolves.toEqual({ id: USER_ID });
    });

    it('returns { id } when INSERT conflicts (existing rootPublicKey — idempotent upsert)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: USER_ID }] as never);
      await expect(upsertUser(ROOT_PUBLIC_KEY)).resolves.toEqual({ id: USER_ID });
    });

    it('throws "upsertUser returned no row" when INSERT returns empty array', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(upsertUser(ROOT_PUBLIC_KEY)).rejects.toThrow('upsertUser returned no row');
    });

    it('executes INSERT with the provided rootPublicKey', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: USER_ID }] as never);
      await upsertUser(ROOT_PUBLIC_KEY);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([ROOT_PUBLIC_KEY]));
    });
  });

  describe('getUserById', () => {
    it('returns { id, root_public_key } when user exists', async () => {
      const row = { id: USER_ID, root_public_key: ROOT_PUBLIC_KEY };
      vi.mocked(sql).mockResolvedValueOnce([row] as never);
      await expect(getUserById(USER_ID)).resolves.toEqual(row);
    });

    it('returns undefined when no user matches id', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getUserById(USER_ID)).resolves.toBeUndefined();
    });
  });

  describe('getUserByRootPublicKey', () => {
    it('returns { id } when user exists with matching root_public_key', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: USER_ID }] as never);
      await expect(getUserByRootPublicKey(ROOT_PUBLIC_KEY)).resolves.toEqual({ id: USER_ID });
    });

    it('returns undefined when no user matches root_public_key', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(getUserByRootPublicKey(ROOT_PUBLIC_KEY)).resolves.toBeUndefined();
    });
  });
});

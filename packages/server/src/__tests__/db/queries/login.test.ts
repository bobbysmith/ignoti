import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { sql } from '../../../db/client.js';
import { incrementSignCountWithChallenge } from '../../../db/queries/login.js';

vi.mock('../../../db/client.js', () => {
  const sqlFn = vi.fn();
  Object.assign(sqlFn, { begin: vi.fn() });
  return { sql: sqlFn };
});

const DEVICE_ID = 'device-uuid-abcd';
const CHALLENGE_VALUE = 'test-challenge-value';
const EXPIRES_AT = new Date('2026-01-01T00:00:00Z');
const NEW_COUNTER = 5;

describe('login db queries', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('incrementSignCountWithChallenge', () => {
    const sqlWithBegin = sql as unknown as Mock & { begin: Mock };

    beforeEach(() => {
      sqlWithBegin.begin = vi.fn(async (fn: (tx: Mock) => Promise<unknown>) =>
        fn(sql as unknown as Mock)
      );
    });

    it('wraps both statements in a transaction', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT);
      expect(sqlWithBegin.begin).toHaveBeenCalledOnce();
    });

    it('returns true when sign count is successfully incremented', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(
        incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT)
      ).resolves.toBe(true);
    });

    it('returns false when sign_count guard blocks the update (stale or replayed counter)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(
        incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT)
      ).resolves.toBe(false);
    });

    it('does not insert the challenge when the update is blocked', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT);
      expect(vi.mocked(sql).mock.calls).toHaveLength(1);
    });

    it('updates devices with sign_count guard as the first query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT);
      const firstQuery = vi.mocked(sql).mock.calls[0][0] as readonly string[];
      expect(firstQuery.join('')).toContain('update devices');
      expect(firstQuery.join('')).toContain('sign_count');
      expect(firstQuery.join('')).toContain('sign_count <');
    });

    it('inserts the session challenge as the second query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT);
      const secondQuery = vi.mocked(sql).mock.calls[1][0] as readonly string[];
      expect(secondQuery.join('')).toContain('insert into challenges');
    });

    it('passes all arguments to their respective queries', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ id: DEVICE_ID }] as never);
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await incrementSignCountWithChallenge(DEVICE_ID, NEW_COUNTER, CHALLENGE_VALUE, EXPIRES_AT);
      expect(vi.mocked(sql).mock.calls[0]).toEqual(
        expect.arrayContaining([DEVICE_ID, NEW_COUNTER])
      );
      expect(vi.mocked(sql).mock.calls[1]).toEqual(
        expect.arrayContaining([CHALLENGE_VALUE, DEVICE_ID, EXPIRES_AT])
      );
    });
  });
});

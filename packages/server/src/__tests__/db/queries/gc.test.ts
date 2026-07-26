import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { sql } from '../../../db/client.js';
import { runGc } from '../../../db/queries/gc.js';

vi.mock('../../../db/client.js', () => {
  const sqlFn = vi.fn();
  Object.assign(sqlFn, { begin: vi.fn() });
  return { sql: sqlFn };
});

describe('runGc', () => {
  const sqlWithBegin = sql as unknown as Mock & { begin: Mock };

  beforeEach(() => {
    vi.resetAllMocks();
    sqlWithBegin.begin = vi.fn(async (fn: (tx: Mock) => Promise<unknown>) =>
      fn(sql as unknown as Mock)
    );
  });

  it('acquires the advisory lock, runs ghostid_gc(), and returns true', async () => {
    vi.mocked(sql).mockResolvedValueOnce([{ locked: true }] as never);
    vi.mocked(sql).mockResolvedValueOnce(undefined as never);
    await expect(runGc()).resolves.toBe(true);
    expect(sql).toHaveBeenCalledTimes(2);
  });

  it('returns false without sweeping when another instance holds the lock', async () => {
    vi.mocked(sql).mockResolvedValueOnce([{ locked: false }] as never);
    await expect(runGc()).resolves.toBe(false);
    expect(sql).toHaveBeenCalledTimes(1);
  });

  it('returns false when the lock query yields no row', async () => {
    vi.mocked(sql).mockResolvedValueOnce([] as never);
    await expect(runGc()).resolves.toBe(false);
    expect(sql).toHaveBeenCalledTimes(1);
  });
});

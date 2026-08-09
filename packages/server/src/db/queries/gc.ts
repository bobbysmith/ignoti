import { sql } from '../client.js';

// Arbitrary fixed key identifying the GC advisory lock. Any instance may hold
// it; the number only needs to be stable and distinct from other advisory
// locks the app might take.
const GC_ADVISORY_LOCK_KEY = 4_927_001;

/**
 * Runs ignoti_gc() under a transaction-scoped advisory lock so that at most
 * one instance sweeps at a time; the lock releases automatically at commit.
 * Returns false without sweeping if another instance holds the lock.
 */
export async function runGc(): Promise<boolean> {
  return sql.begin(async tx => {
    const [row] = await tx<{ locked: boolean }[]>`
      select pg_try_advisory_xact_lock(${GC_ADVISORY_LOCK_KEY}) as locked
    `;
    if (!row?.locked) {
      return false;
    }
    await tx`select ignoti_gc()`;
    return true;
  });
}

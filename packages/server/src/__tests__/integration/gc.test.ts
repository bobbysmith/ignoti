import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../db/client.js';
import { runGc } from '../../db/queries/gc.js';
import { cleanDatabase, runMigrations } from './helpers.js';

function first<T>(rows: readonly T[]): T {
  const [row] = rows;
  if (!row) {
    throw new Error('expected insert to return a row');
  }
  return row;
}

describe('Integration: ghostid_gc', () => {
  beforeAll(async () => {
    await runMigrations();
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await sql.end();
  });

  it('purges devices revoked past the 7-day grace and keeps recent/active ones', async () => {
    const user = first(
      await sql`
      insert into users (root_public_key) values ('gc-test-root-key') returning id
    `
    );
    const oldRevoked = first(
      await sql`
      insert into devices (user_id, credential_id, passkey_public_key, revoked_at)
      values (${user.id}, 'gc-old-cred', 'pk', now() - interval '8 days')
      returning id
    `
    );
    const recentRevoked = first(
      await sql`
      insert into devices (user_id, credential_id, passkey_public_key, revoked_at)
      values (${user.id}, 'gc-recent-cred', 'pk', now() - interval '1 day')
      returning id
    `
    );
    const active = first(
      await sql`
      insert into devices (user_id, credential_id, passkey_public_key)
      values (${user.id}, 'gc-active-cred', 'pk')
      returning id
    `
    );

    await sql`select ghostid_gc()`;

    const remaining = (await sql`select id from devices where user_id = ${user.id}`).map(r => r.id);
    expect(remaining).not.toContain(oldRevoked.id);
    expect(remaining).toContain(recentRevoked.id);
    expect(remaining).toContain(active.id);
  });

  it('purges expired session nonces and keeps live ones', async () => {
    const expired = crypto.randomUUID();
    const live = crypto.randomUUID();
    await sql`
      insert into session_nonces (jti, expires_at)
      values (${expired}, now() - interval '1 minute'), (${live}, now() + interval '1 minute')
    `;

    await sql`select ghostid_gc()`;

    const remaining = (await sql`select jti from session_nonces`).map(r => r.jti);
    expect(remaining).not.toContain(expired);
    expect(remaining).toContain(live);
  });

  it('runGc() acquires the advisory lock and purges expired challenges', async () => {
    const expired = 'gc-runner-expired';
    const live = 'gc-runner-live';
    await sql`
      insert into challenges (value, purpose, expires_at)
      values
        (${expired}, 'login', now() - interval '1 minute'),
        (${live}, 'login', now() + interval '1 minute')
    `;

    const ran = await runGc();
    expect(ran).toBe(true);

    const remaining = (await sql`select value from challenges`).map(r => r.value);
    expect(remaining).not.toContain(expired);
    expect(remaining).toContain(live);
  });

  it('runGc() reports false and does not block when the lock is already held', async () => {
    await sql.begin(async tx => {
      const [row] = await tx<{ locked: boolean }[]>`
        select pg_try_advisory_xact_lock(4927001) as locked
      `;
      expect(row?.locked).toBe(true);
      // A concurrent sweep on a different pooled connection cannot get the lock.
      expect(await runGc()).toBe(false);
    });
  });
});

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../db/client.js';
import { cleanDatabase, runMigrations } from './helpers.js';

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
    const [user] = await sql`
      insert into users (root_public_key) values ('gc-test-root-key') returning id
    `;
    const [oldRevoked] = await sql`
      insert into devices (user_id, credential_id, passkey_public_key, revoked_at)
      values (${user!.id}, 'gc-old-cred', 'pk', now() - interval '8 days')
      returning id
    `;
    const [recentRevoked] = await sql`
      insert into devices (user_id, credential_id, passkey_public_key, revoked_at)
      values (${user!.id}, 'gc-recent-cred', 'pk', now() - interval '1 day')
      returning id
    `;
    const [active] = await sql`
      insert into devices (user_id, credential_id, passkey_public_key)
      values (${user!.id}, 'gc-active-cred', 'pk')
      returning id
    `;

    await sql`select ghostid_gc()`;

    const remaining = (await sql`select id from devices where user_id = ${user!.id}`).map(
      r => r.id
    );
    expect(remaining).not.toContain(oldRevoked!.id);
    expect(remaining).toContain(recentRevoked!.id);
    expect(remaining).toContain(active!.id);
  });
});

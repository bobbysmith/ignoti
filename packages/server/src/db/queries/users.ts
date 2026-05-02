import { sql } from '../client';

interface UserRow {
  id: string;
  root_public_key: string;
}

interface UserId {
  id: string;
}

export async function upsertUser(rootPublicKey: string): Promise<UserId> {
  const [user] = await sql<UserId[]>`
    with ins as (
      insert into users (root_public_key)
      values (${rootPublicKey})
      on conflict (root_public_key) do nothing
      returning id
    )
    select id from ins
    union all
    select id from users where root_public_key = ${rootPublicKey}
    limit 1
  `;
  if (!user) throw new Error('upsertUser returned no row');
  return user;
}

export async function getUserById(id: string): Promise<UserRow | undefined> {
  const [user] = await sql<UserRow[]>`
    select id, root_public_key from users where id = ${id}
  `;
  return user;
}

export async function getUserByRootPublicKey(rootPublicKey: string): Promise<UserId | undefined> {
  const [user] = await sql<UserId[]>`
    select id from users where root_public_key = ${rootPublicKey}
  `;
  return user;
}

import { sql } from '../client.js';

interface UserRow {
  id: string;
  root_public_key: string;
}

interface UserId {
  id: string;
}

// Separate statements: the SELECT needs a snapshot taken after a concurrent
// insert of the same key commits.
export async function upsertUser(rootPublicKey: string): Promise<UserId> {
  const [inserted] = await sql<UserId[]>`
    insert into users (root_public_key)
    values (${rootPublicKey})
    on conflict (root_public_key) do nothing
    returning id
  `;
  if (inserted) return inserted;

  const [existing] = await sql<UserId[]>`
    select id from users where root_public_key = ${rootPublicKey}
  `;
  if (!existing) throw new Error('upsertUser returned no row');
  return existing;
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

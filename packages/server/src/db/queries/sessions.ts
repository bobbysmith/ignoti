import { sql } from '../client.js';

interface InsertSessionParams {
  deviceId: string;
  sessionPublicKey: string;
  expiresAt: Date;
}

interface RebindRow {
  user_id: string;
  device_id: string;
  expires_at: Date;
}

interface SessionAuthRow {
  session_public_key: string;
  user_id: string;
  device_id: string;
}

interface SessionListRow {
  id: string;
  device_id: string;
  created_at: Date;
  last_used_at: Date | null;
  expires_at: Date;
}

interface SessionRow {
  id: string;
  expires_at: Date;
}

export async function insertSession(params: InsertSessionParams): Promise<SessionRow> {
  const [session] = await sql<SessionRow[]>`
    insert into sessions (device_id, session_public_key, expires_at)
    values (${params.deviceId}, ${params.sessionPublicKey}, ${params.expiresAt})
    returning id, expires_at
  `;
  if (!session) throw new Error('insertSession returned no row');
  return session;
}

export async function getSessionWithUser(sessionId: string): Promise<SessionAuthRow | undefined> {
  const [row] = await sql<SessionAuthRow[]>`
    select s.session_public_key, s.device_id, d.user_id
    from sessions s
    join devices d on d.id = s.device_id
    where s.id = ${sessionId}
      and s.revoked_at is null
      and s.expires_at > now()
  `;
  return row;
}

export async function touchSession(sessionId: string): Promise<void> {
  await sql`
    update sessions set last_used_at = now()
    where id = ${sessionId}
  `;
}

export async function getSessionsForUser(userId: string): Promise<SessionListRow[]> {
  return sql<SessionListRow[]>`
    select s.id, s.device_id, s.created_at, s.last_used_at, s.expires_at
    from sessions s
    join devices d on d.id = s.device_id
    where d.user_id = ${userId}
      and s.revoked_at is null
      and s.expires_at > now()
    order by s.created_at desc
  `;
}

export async function rebindSessionPublicKey(
  sessionId: string,
  newPublicKey: string
): Promise<RebindRow | undefined> {
  const [row] = await sql<RebindRow[]>`
    update sessions s
    set session_public_key = ${newPublicKey}
    from devices d
    where s.id = ${sessionId}
      and s.device_id = d.id
      and s.revoked_at is null
      and s.expires_at > now()
    returning d.user_id, s.device_id, s.expires_at
  `;
  return row;
}

export async function revokeSessionForUser(sessionId: string, userId: string): Promise<boolean> {
  const [row] = await sql<{ id: string }[]>`
    update sessions set revoked_at = now()
    where id = ${sessionId}
      and revoked_at is null
      and device_id in (
        select id from devices where user_id = ${userId} and revoked_at is null
      )
    returning id
  `;
  return row !== undefined;
}

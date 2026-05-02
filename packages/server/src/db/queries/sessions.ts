import { sql } from '../client';

interface InsertSessionParams {
  deviceId: string;
  sessionPublicKey: string;
  expiresAt: Date;
}

interface SessionRow {
  id: string;
  expires_at: Date;
}

export interface SessionAuthRow {
  session_public_key: string;
  expires_at: Date;
  revoked_at: Date | null;
  user_id: string;
  device_id: string;
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
    select s.session_public_key, s.expires_at, s.revoked_at, s.device_id, d.user_id
    from sessions s
    join devices d on d.id = s.device_id
    where s.id = ${sessionId}
  `;
  return row;
}

export async function touchSession(sessionId: string): Promise<void> {
  await sql`
    update sessions set last_used_at = now()
    where id = ${sessionId}
  `;
}

export async function revokeSessionsByDevice(deviceId: string): Promise<void> {
  await sql`
    update sessions set revoked_at = now()
    where device_id = ${deviceId} and revoked_at is null
  `;
}

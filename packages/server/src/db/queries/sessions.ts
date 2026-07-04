import { sql } from '../client.js';

interface InsertSessionParams {
  deviceId: string;
  sessionPublicKey: string;
  restoreTokenHash: string;
  expiresAt: Date;
}

interface RotateRow {
  user_id: string;
  device_id: string;
  expires_at: Date;
}

interface SessionAuthRow {
  session_public_key: string;
  user_id: string;
  device_id: string;
  expires_at: Date;
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
    insert into sessions (device_id, session_public_key, restore_token_hash, expires_at)
    values (
      ${params.deviceId},
      ${params.sessionPublicKey},
      ${params.restoreTokenHash},
      ${params.expiresAt}
    )
    returning id, expires_at
  `;
  if (!session) throw new Error('insertSession returned no row');
  return session;
}

export async function getSessionWithUser(sessionId: string): Promise<SessionAuthRow | undefined> {
  const [row] = await sql<SessionAuthRow[]>`
    select s.session_public_key, s.device_id, s.expires_at, d.user_id
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

/**
 * Restore with rotation: atomically rebinds the session public key AND rotates
 * the restore-token hash, but only when the presented hash matches the current
 * one on an active session. Returns undefined on any mismatch (wrong/replayed
 * secret, revoked, or expired) - the caller treats a mismatch on a still active
 * session as token reuse.
 */
export async function rotateSessionOnRestore(
  sessionId: string,
  presentedHash: string,
  newHash: string,
  newPublicKey: string
): Promise<RotateRow | undefined> {
  const [row] = await sql<RotateRow[]>`
    update sessions s
    set session_public_key = ${newPublicKey}, restore_token_hash = ${newHash}
    from devices d
    where s.id = ${sessionId}
      and s.device_id = d.id
      and s.restore_token_hash = ${presentedHash}
      and s.revoked_at is null
      and s.expires_at > now()
    returning d.user_id, s.device_id, s.expires_at
  `;
  return row;
}

/**
 * Revokes a single active session by id, independent of ownership. Used by the
 * restore path when token reuse is detected. Returns true if a live session was
 * revoked (i.e. the reuse hit an active session), false if it was already
 * inactive.
 */
export async function revokeSessionById(sessionId: string): Promise<boolean> {
  const [row] = await sql<{ id: string }[]>`
    update sessions set revoked_at = now()
    where id = ${sessionId}
      and revoked_at is null
      and expires_at > now()
    returning id
  `;
  return row !== undefined;
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

export async function revokeAllSessionsForUser(userId: string): Promise<number> {
  const rows = await sql<{ id: string }[]>`
    update sessions set revoked_at = now()
    where revoked_at is null
      and device_id in (
        select id from devices where user_id = ${userId} and revoked_at is null
      )
    returning id
  `;
  return rows.length;
}

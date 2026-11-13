import { sql } from '../client.js';

interface InsertSessionParams {
  deviceId: string;
  sessionPublicKey: string;
  restoreTokenHash: string;
  restoreFamilyHash: string;
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
  revoked_at: Date | null;
  device_revoked_at: Date | null;
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
    insert into sessions (
      device_id, session_public_key, restore_token_hash, restore_family_hash, expires_at
    )
    values (
      ${params.deviceId},
      ${params.sessionPublicKey},
      ${params.restoreTokenHash},
      ${params.restoreFamilyHash},
      ${params.expiresAt}
    )
    returning id, expires_at
  `;
  if (!session) throw new Error('insertSession returned no row');
  return session;
}

// Returns the row regardless of revoked/expired state; the caller verifies the
// signature first, then classifies (revoked vs expired vs active), so only the
// session-key holder learns the granular state.
export async function getSessionWithUser(sessionId: string): Promise<SessionAuthRow | undefined> {
  const [row] = await sql<SessionAuthRow[]>`
    select s.session_public_key, s.device_id, s.expires_at, s.revoked_at, d.user_id,
           d.revoked_at as device_revoked_at
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

export async function getSessionsForUser(userId: string): Promise<SessionListRow[]> {
  return sql<SessionListRow[]>`
    select s.id, s.device_id, s.created_at, s.last_used_at, s.expires_at
    from sessions s
    join devices d on d.id = s.device_id
    where d.user_id = ${userId}
      and d.revoked_at is null
      and s.revoked_at is null
      and s.expires_at > now()
    order by s.created_at desc
  `;
}

/**
 * Restore with rotation: rotates the restore-token hash, but only when the
 * family hash, the presented secret hash, and the session public key all match
 * an active session. The public key is never changed. Returns undefined on any
 * mismatch (wrong/replayed secret, wrong family, wrong key, revoked, or expired).
 */
export async function rotateSessionOnRestore(
  sessionId: string,
  familyHash: string,
  presentedHash: string,
  newHash: string,
  sessionPublicKey: string
): Promise<RotateRow | undefined> {
  const [row] = await sql<RotateRow[]>`
    update sessions s
    set restore_token_hash = ${newHash}
    from devices d
    where s.id = ${sessionId}
      and s.device_id = d.id
      and s.restore_family_hash = ${familyHash}
      and s.restore_token_hash = ${presentedHash}
      and s.session_public_key = ${sessionPublicKey}
      and d.revoked_at is null
      and s.revoked_at is null
      and s.expires_at > now()
    returning d.user_id, s.device_id, s.expires_at
  `;
  return row;
}

/**
 * Revokes a session whose cookie failed to restore. Call only after
 * rotateSessionOnRestore has rejected the request: a matching family then means
 * an earlier cookie is being replayed, or the caller lacks the session key.
 * A wrong family must not revoke: session ids are not secret, so that would be
 * a remote DoS.
 */
export async function revokeSessionOnRestoreReuse(
  sessionId: string,
  familyHash: string
): Promise<boolean> {
  const [row] = await sql<{ id: string }[]>`
    update sessions set revoked_at = now()
    where id = ${sessionId}
      and revoked_at is null
      and expires_at > now()
      and restore_family_hash = ${familyHash}
    returning id
  `;
  return row !== undefined;
}

export async function revokeSessionForUser(sessionId: string, userId: string): Promise<boolean> {
  const [row] = await sql<{ id: string }[]>`
    update sessions set revoked_at = now()
    where id = ${sessionId}
      and revoked_at is null
      and expires_at > now()
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

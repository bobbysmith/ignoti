import { sql } from '../client.js';

/**
 * Single-use insert: returns false when the jti has already been stored, i.e.
 * the request is a replay. The primary-key conflict is the atomic check and
 * holds across all server instances sharing the database.
 */
export async function storeNonce(jti: string, expiresAt: Date): Promise<boolean> {
  const rows = await sql<{ jti: string }[]>`
    insert into session_nonces (jti, expires_at)
    values (${jti}, ${expiresAt})
    on conflict (jti) do nothing
    returning jti
  `;
  return rows.length > 0;
}

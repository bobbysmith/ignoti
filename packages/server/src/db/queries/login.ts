import { CHALLENGE_PURPOSE } from '../../constants';
import { sql } from '../client';

export async function incrementSignCountWithChallenge(
  deviceId: string,
  newCounter: number,
  sessionChallenge: string,
  expiresAt: Date
): Promise<void> {
  await sql.begin(async tx => {
    await tx`
      update devices set sign_count = ${newCounter}, last_used_at = now()
      where id = ${deviceId}
    `;
    await tx`
      insert into challenges (value, purpose, device_id, expires_at)
      values (${sessionChallenge}, ${CHALLENGE_PURPOSE.SESSION}, ${deviceId}, ${expiresAt})
    `;
  });
}

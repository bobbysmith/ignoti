import { CHALLENGE_PURPOSE } from '../../constants';
import { sql } from '../client';

export async function incrementSignCountWithChallenge(
  deviceId: string,
  newCounter: number,
  sessionChallenge: string,
  expiresAt: Date
): Promise<boolean> {
  return sql.begin(async tx => {
    const [updated] = await tx<{ id: string }[]>`
      update devices set sign_count = ${newCounter}, last_used_at = now()
      where id = ${deviceId}
        and sign_count < ${newCounter}
      returning id
    `;

    if (!updated) {
      return false;
    }

    await tx`
      insert into challenges (value, purpose, device_id, expires_at)
      values (${sessionChallenge}, ${CHALLENGE_PURPOSE.SESSION}, ${deviceId}, ${expiresAt})
    `;

    return true;
  });
}

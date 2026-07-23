import { CHALLENGE_PURPOSE } from '../../constants.js';
import { sql } from '../client.js';

export async function incrementSignCountWithChallenge(
  deviceId: string,
  newCounter: number,
  sessionChallenge: string,
  expiresAt: Date
): Promise<boolean> {
  return sql.begin(async tx => {
    // newCounter = 0 is allowed: platform authenticators (Touch ID, Face ID,
    // Windows Hello) always report zero, which the spec permits. Clone detection
    // via strict monotonicity does not apply to them.
    const [updated] = await tx<{ id: string }[]>`
      update devices set sign_count = ${newCounter}, last_used_at = now()
      where id = ${deviceId}
        and (${newCounter} = 0 or sign_count < ${newCounter})
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

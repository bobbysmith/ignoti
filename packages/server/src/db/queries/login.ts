import { CHALLENGE_PURPOSE } from '../../constants.js';
import { sql } from '../client.js';

export async function incrementSignCountWithChallenge(
  deviceId: string,
  newCounter: number,
  sessionChallenge: string,
  expiresAt: Date
): Promise<boolean> {
  return sql.begin(async tx => {
    // The `${newCounter} = 0` branch permits authenticators that always report a
    // zero counter (Touch ID, Face ID, Windows Hello — the spec allows this).
    // Clone detection via strict monotonicity is therefore disabled for them by
    // design; do not "fix" this into rejecting zero counters.
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

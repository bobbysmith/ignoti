import { CHALLENGE_PURPOSE } from '../../constants';
import { sql } from '../client';

interface ChallengeValue {
  value: string;
}

interface SessionChallengeRow {
  device_id: string;
}

export async function insertLoginChallenge(value: string, expiresAt: Date): Promise<void> {
  await sql`
    insert into challenges (value, purpose, expires_at)
    values (${value}, ${CHALLENGE_PURPOSE.LOGIN}, ${expiresAt})
  `;
}

export async function insertRecoverChallenge(
  value: string,
  userId: string,
  expiresAt: Date
): Promise<void> {
  await sql`
    insert into challenges (value, purpose, user_id, expires_at)
    values (${value}, ${CHALLENGE_PURPOSE.RECOVER}, ${userId}, ${expiresAt})
  `;
}

export async function insertRegisterChallenge(
  value: string,
  userId: string,
  expiresAt: Date
): Promise<void> {
  await sql`
    insert into challenges (value, purpose, user_id, expires_at)
    values (${value}, ${CHALLENGE_PURPOSE.REGISTER}, ${userId}, ${expiresAt})
  `;
}

export async function insertSessionChallenge(
  value: string,
  deviceId: string,
  expiresAt: Date
): Promise<void> {
  await sql`
    insert into challenges (value, purpose, device_id, expires_at)
    values (${value}, ${CHALLENGE_PURPOSE.SESSION}, ${deviceId}, ${expiresAt})
  `;
}

export async function consumeLoginChallenge(value: string): Promise<boolean> {
  const [row] = await sql<ChallengeValue[]>`
    update challenges
    set consumed_at = now()
    where value = ${value}
      and purpose = ${CHALLENGE_PURPOSE.LOGIN}
      and consumed_at is null
      and expires_at > now()
    returning value
  `;
  return row !== undefined;
}

export async function consumeRecoverChallenge(value: string, userId: string): Promise<boolean> {
  const [row] = await sql<ChallengeValue[]>`
    update challenges
    set consumed_at = now()
    where value = ${value}
      and purpose = ${CHALLENGE_PURPOSE.RECOVER}
      and user_id = ${userId}
      and consumed_at is null
      and expires_at > now()
    returning value
  `;
  return row !== undefined;
}

export async function consumeRegisterChallenge(value: string, userId: string): Promise<boolean> {
  const [row] = await sql<ChallengeValue[]>`
    update challenges
    set consumed_at = now()
    where value = ${value}
      and purpose = ${CHALLENGE_PURPOSE.REGISTER}
      and user_id = ${userId}
      and consumed_at is null
      and expires_at > now()
    returning value
  `;
  return row !== undefined;
}

export async function consumeSessionChallenge(
  value: string
): Promise<SessionChallengeRow | undefined> {
  const [row] = await sql<SessionChallengeRow[]>`
    update challenges
    set consumed_at = now()
    where value = ${value}
      and purpose = ${CHALLENGE_PURPOSE.SESSION}
      and consumed_at is null
      and expires_at > now()
    returning device_id
  `;
  return row;
}
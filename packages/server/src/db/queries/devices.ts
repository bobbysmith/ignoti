import { sql } from '../client';

interface DeviceRow {
  id: string;
  credential_id: string;
  passkey_public_key: string;
  sign_count: bigint;
  transports: string[] | null;
}

interface DeviceWithUser {
  user_id: string;
  credential_id: string;
}

interface InsertDeviceParams {
  userId: string;
  credentialId: string;
  passkeyPublicKey: string;
  signCount: number;
  transports: string[] | null;
  deviceName: string | null;
}

interface DeviceListItem {
  id: string;
  credential_id: string;
  device_name: string | null;
  created_at: Date;
  last_used_at: Date | null;
}

interface DeviceId {
  id: string;
}

export async function getDevicesForUser(userId: string): Promise<DeviceListItem[]> {
  return sql<DeviceListItem[]>`
    select id, credential_id, device_name, created_at, last_used_at
    from devices
    where user_id = ${userId} and revoked_at is null
    order by created_at desc
  `;
}

export async function getDeviceByCredentialId(
  credentialId: string
): Promise<DeviceRow | undefined> {
  const [device] = await sql<DeviceRow[]>`
    select id, credential_id, passkey_public_key, sign_count, transports
    from devices
    where credential_id = ${credentialId} and revoked_at is null
  `;
  return device;
}

export async function getDeviceById(id: string): Promise<DeviceWithUser | undefined> {
  const [device] = await sql<DeviceWithUser[]>`
    select user_id, credential_id from devices where id = ${id} and revoked_at is null
  `;
  return device;
}

export async function insertDevice(params: InsertDeviceParams): Promise<DeviceId> {
  const [device] = await sql<DeviceId[]>`
    insert into devices (
      user_id, credential_id, passkey_public_key, sign_count, transports, device_name
    ) values (
      ${params.userId},
      ${params.credentialId},
      ${params.passkeyPublicKey},
      ${params.signCount},
      ${params.transports},
      ${params.deviceName}
    )
    returning id
  `;
  if (!device) throw new Error('insertDevice returned no row');
  return device;
}

export async function updateDeviceSignCount(deviceId: string, newCounter: number): Promise<void> {
  await sql`
    update devices
    set sign_count = ${newCounter}, last_used_at = now()
    where id = ${deviceId}
  `;
}

export async function revokeDeviceWithSessions(deviceId: string): Promise<void> {
  await sql.begin(async tx => {
    await tx`
      update devices set revoked_at = now()
      where id = ${deviceId} and revoked_at is null
    `;
    await tx`
      update sessions set revoked_at = now()
      where device_id = ${deviceId} and revoked_at is null
    `;
  });
}

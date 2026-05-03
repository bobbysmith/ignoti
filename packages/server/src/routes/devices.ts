import type { FastifyInstance } from 'fastify';
import { ERROR_CODES, RATE_LIMITS, ROUTES } from '../constants';
import {
  getDeviceById,
  getDevicesForUser,
  revokeDeviceWithSessions,
} from '../db/queries/devices.js';
import { getUserById } from '../db/queries/users.js';
import { sendError } from '../helpers/response.js';
import { verifyDeviceBindingJWS } from '../lib/root-jws.js';
import { requireSession } from '../plugins/session-auth.js';
import { revokeDeviceBody, revokeDeviceParams } from '../schemas/devices.js';

export async function registerDeviceRoutes(app: FastifyInstance) {
  /**
   * GET /api/devices
   * Returns: { devices: DeviceListItem[] }
   *
   * Lists all active (non-revoked) devices for the authenticated user.
   */
  app.get(ROUTES.DEVICES.LIST, { preHandler: [requireSession] }, async (req, reply) => {
    // biome-ignore lint/style/noNonNullAssertion: requireSession preHandler guarantees non-null
    const { userId } = req.sessionContext!;
    const rows = await getDevicesForUser(userId);
    const devices = rows.map(d => ({
      id: d.id,
      credentialId: d.credential_id,
      deviceName: d.device_name,
      createdAt: d.created_at.toISOString(),
      lastUsedAt: d.last_used_at?.toISOString() ?? null,
    }));
    return reply.send({ devices });
  });

  /**
   * DELETE /api/devices/:id
   * Body: { rootSignature }  (compact JWS, EdDSA, purpose: revoke-device)
   * Returns: { ok: true }
   *
   * The JWS must carry purpose='revoke-device', the device's userId,
   * credentialId, and challenge equal to the deviceId (the URL param).
   * Using the deviceId as the challenge binds the JWS to this specific
   * revocation and prevents it from being replayed against a different device.
   */
  // No requireSession: revocation is authorized by the root JWS alone so that a
  // user who has lost all active sessions can still revoke devices using their mnemonic.
  app.delete(
    ROUTES.DEVICES.REVOKE,
    { config: { rateLimit: RATE_LIMITS.RECOVER } },
    async (req, reply) => {
      const parsedParams = revokeDeviceParams.safeParse(req.params);
      if (!parsedParams.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsedParams.error.flatten());
      }
      const { id: deviceId } = parsedParams.data;

      const parsedBody = revokeDeviceBody.safeParse(req.body);
      if (!parsedBody.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsedBody.error.flatten());
      }
      const { rootSignature } = parsedBody.data;

      const device = await getDeviceById(deviceId);
      if (!device) {
        return sendError(reply, 404, ERROR_CODES.DEVICE_NOT_FOUND);
      }

      const user = await getUserById(device.user_id);
      if (!user) {
        return sendError(reply, 404, ERROR_CODES.USER_NOT_FOUND);
      }

      try {
        await verifyDeviceBindingJWS(rootSignature, user.root_public_key, {
          purpose: 'revoke-device',
          userId: device.user_id,
          credentialId: device.credential_id,
          challenge: deviceId,
        });
      } catch (err) {
        req.log.warn({ err }, 'root signature verification failed');
        return sendError(reply, 401, ERROR_CODES.INVALID_ROOT_SIGNATURE);
      }

      await revokeDeviceWithSessions(deviceId);
      req.log.info({ deviceId, userId: device.user_id }, 'device revoked');

      return reply.send({ ok: true });
    }
  );
}

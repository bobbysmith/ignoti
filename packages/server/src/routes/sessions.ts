import type { FastifyInstance } from 'fastify';
import { ERROR_CODES, ROUTES } from '../constants.js';
import {
  getSessionsForUser,
  revokeAllSessionsForUser,
  revokeSessionForUser,
} from '../db/queries/sessions.js';
import { sendError } from '../helpers/response.js';
import { createIntrospectionAuth } from '../lib/introspection-auth.js';
import { clearSessionCookie } from '../lib/session-cookie.js';
import { requireSession, verifySessionAuth } from '../plugins/session-auth.js';
import { revokeSessionParams, verifySessionBody } from '../schemas/sessions.js';

export async function registerSessionRoutes(app: FastifyInstance) {
  /**
   * POST /api/sessions/verify
   * Headers: Authorization: Bearer <INTROSPECTION_SECRET>
   * Body: { method, url, authorization, nonce, timestamp, signature }
   * Returns: 200 { valid: true, sessionId, userId, deviceId, expiresAt }
   *        | 200 { valid: false, error }  (RFC 7662-style: an invalid session
   *          is a successful introspection, not a failed request)
   *        | 401 when the introspection secret is missing or wrong
   *
   * Lets an integrator's own backend validate the session headers the SDK
   * produced via getSessionHeaders(). The backend forwards the four header
   * values plus the method and full URL of the request it received; verification
   * runs the exact same checks as Ignoti's own protected routes, including
   * nonce replay prevention — so verify each request exactly once.
   */
  // Not rate limited: every call comes from the integrator backend's IP, and
  // callers without the introspection secret are rejected before any work.
  app.post(
    ROUTES.SESSIONS.VERIFY,
    { config: { rateLimit: false }, onRequest: createIntrospectionAuth() },
    async (req, reply) => {
      const parsed = verifySessionBody.safeParse(req.body);
      if (!parsed.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsed.error.flatten());
      }
      const { method, url, authorization, nonce, timestamp, signature } = parsed.data;

      const result = await verifySessionAuth(
        { authorization, nonce, timestamp, signature, method, url },
        req.log
      );

      if (!result.ok) {
        return reply.send({ valid: false, error: result.code });
      }

      return reply.send({
        valid: true,
        sessionId: result.context.sessionId,
        userId: result.context.userId,
        deviceId: result.context.deviceId,
        expiresAt: result.expiresAt.getTime(),
      });
    }
  );

  /**
   * GET /api/sessions
   * Returns: { sessions: SessionListItem[] }
   *
   * Lists all active (non-revoked, non-expired) sessions for the authenticated
   * user. `isCurrent` flags the session making this request so clients can
   * surface a "log out other devices" UI without hard-coding session IDs.
   */
  app.get(ROUTES.SESSIONS.LIST, { preHandler: [requireSession] }, async (req, reply) => {
    // biome-ignore lint/style/noNonNullAssertion: requireSession preHandler guarantees non-null
    const { userId, sessionId: currentSessionId } = req.sessionContext!;
    const rows = await getSessionsForUser(userId);
    const sessions = rows.map(s => ({
      id: s.id,
      deviceId: s.device_id,
      createdAt: s.created_at.toISOString(),
      lastUsedAt: s.last_used_at?.toISOString() ?? null,
      expiresAt: s.expires_at.toISOString(),
      isCurrent: s.id === currentSessionId,
    }));
    return reply.send({ sessions });
  });

  /**
   * DELETE /api/sessions/:id
   * Returns: { ok: true }
   *
   * Revokes a single session without touching the device passkey, so the user
   * can still log back in. Ownership is enforced server-side: only sessions
   * belonging to the authenticated user can be revoked. Returns 404 for both
   * not-found and not-owned cases to avoid leaking session existence.
   *
   * A user may revoke their own current session to implement "log out".
   */
  app.delete(ROUTES.SESSIONS.REVOKE, { preHandler: [requireSession] }, async (req, reply) => {
    const parsedParams = revokeSessionParams.safeParse(req.params);
    if (!parsedParams.success) {
      return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsedParams.error.flatten());
    }
    const { id: targetSessionId } = parsedParams.data;

    // biome-ignore lint/style/noNonNullAssertion: requireSession preHandler guarantees non-null
    const { userId, sessionId: currentSessionId } = req.sessionContext!;

    const revoked = await revokeSessionForUser(targetSessionId, userId);
    if (!revoked) {
      return sendError(reply, 404, ERROR_CODES.SESSION_NOT_FOUND);
    }

    if (targetSessionId === currentSessionId) {
      clearSessionCookie(reply);
    }

    req.log.info({ targetSessionId, currentSessionId, userId }, 'session revoked');
    return reply.send({ ok: true });
  });

  /**
   * DELETE /api/sessions
   * Returns: { revoked: number }
   *
   * Revokes every active session for the authenticated user across all devices,
   * including the current one. Devices remain registered so the user can log
   * back in with any of their passkeys. Clears the session cookie since the
   * current session is now revoked.
   */
  app.delete(ROUTES.SESSIONS.LIST, { preHandler: [requireSession] }, async (req, reply) => {
    // biome-ignore lint/style/noNonNullAssertion: requireSession preHandler guarantees non-null
    const { userId } = req.sessionContext!;
    const revoked = await revokeAllSessionsForUser(userId);
    clearSessionCookie(reply);
    req.log.info({ userId, revoked }, 'all sessions revoked');
    return reply.send({ revoked });
  });
}

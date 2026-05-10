import type { FastifyInstance } from 'fastify';
import { ERROR_CODES, ROUTES, SESSION_COOKIE_NAME } from '../constants.js';
import { getSessionsForUser, revokeSessionForUser } from '../db/queries/sessions.js';
import { sendError } from '../helpers/response.js';
import { requireSession } from '../plugins/session-auth.js';
import { revokeSessionParams } from '../schemas/sessions.js';

export async function registerSessionRoutes(app: FastifyInstance) {
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
      reply.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
    }

    req.log.info({ targetSessionId, currentSessionId, userId }, 'session revoked');
    return reply.send({ ok: true });
  });
}

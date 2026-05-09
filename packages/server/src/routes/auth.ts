import { randomBytes, randomUUID } from 'node:crypto';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { FastifyInstance } from 'fastify';
import { config } from '../config.js';
import {
  ERROR_CODES,
  RATE_LIMITS,
  ROUTES,
  SESSION_CHALLENGE_TTL_MS,
  WEBAUTHN_TIMEOUT_MS,
} from '../constants';
import {
  consumeLoginChallenge,
  consumeRecoverChallenge,
  consumeRegisterChallenge,
  consumeSessionChallenge,
  insertLoginChallenge,
  insertRecoverChallenge,
  insertRegisterChallenge,
  insertSessionChallenge,
  insertTimingRecoverChallenge,
} from '../db/queries/challenges';
import {
  getDeviceByCredentialId,
  getDeviceById,
  insertDevice,
  updateDeviceSignCount,
} from '../db/queries/devices';
import { insertSession } from '../db/queries/sessions';
import { getUserById, getUserByRootPublicKey, upsertUser } from '../db/queries/users';
import { buildRegistrationOptions, extractChallenge } from '../helpers/auth.js';
import { sendError } from '../helpers/response.js';
import { decodeJwt, verifyDeviceBindingJWS } from '../lib/root-jws.js';
import { verifySessionBindingJWS } from '../lib/session-jws.js';
import {
  loginBody,
  recoverBody,
  registerBody,
  registerDeviceBody,
  sessionBody,
} from '../schemas/auth.js';

export async function registerAuthRoutes(app: FastifyInstance) {
  /**
   * POST /api/auth/register
   * Body: { rootPublicKey }
   * Returns: { userId, options }  (options is PublicKeyCredentialCreationOptionsJSON)
   *
   * Idempotent on root_public_key: re-posting returns the existing userId
   * with a fresh challenge so the same mnemonic can re-bootstrap a device.
   */
  app.post(
    ROUTES.AUTH.REGISTER,
    { config: { rateLimit: RATE_LIMITS.REGISTER } },
    async (req, reply) => {
      const parsed = registerBody.safeParse(req.body);
      if (!parsed.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsed.error.flatten());
      }
      const { rootPublicKey } = parsed.data;

      const user = await upsertUser(rootPublicKey);
      const options = await buildRegistrationOptions(user.id);

      const expiresAt = new Date(Date.now() + config.CHALLENGE_TTL_SECONDS * 1000);
      await insertRegisterChallenge(options.challenge, user.id, expiresAt);

      return reply.send({ userId: user.id, options });
    }
  );

  /**
   * POST /api/auth/register/device
   * Verifies (a) the WebAuthn attestation against the stored challenge, and
   * (b) the root-key signature over the canonical
   *     `register-device|{userId}|{credentialId}|{challenge}`.
   * Both must pass before we persist the device. The challenge row is
   * marked consumed atomically so a captured request can't be replayed.
   */
  app.post(
    ROUTES.AUTH.REGISTER_DEVICE,
    { config: { rateLimit: RATE_LIMITS.REGISTER } },
    async (req, reply) => {
      const parsed = registerDeviceBody.safeParse(req.body);
      if (!parsed.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsed.error.flatten());
      }
      const { userId, registrationResponse, rootSignature, deviceName } = parsed.data;

      const user = await getUserById(userId);
      if (!user) {
        return sendError(reply, 404, ERROR_CODES.USER_NOT_FOUND);
      }

      let expectedChallenge: string;
      try {
        expectedChallenge = extractChallenge(registrationResponse);
      } catch (err) {
        req.log.warn({ err }, 'failed to extract challenge from registration response');
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT);
      }

      // Peek at the JWS purpose before consuming the challenge so we consume
      // against the correct purpose column. Cryptographic verification happens
      // below; this decode is unverified and only used to route the DB lookup.
      const allowedPurposes = ['register-device', 'recover-device'] as const;
      let jwsPurpose: (typeof allowedPurposes)[number] = 'register-device';
      try {
        const unverified = decodeJwt(rootSignature);
        if (
          typeof unverified.purpose === 'string' &&
          (allowedPurposes as readonly string[]).includes(unverified.purpose)
        ) {
          jwsPurpose = unverified.purpose as (typeof allowedPurposes)[number];
        }
      } catch {
        // decodeJwt failure means the JWS is malformed; verifyDeviceBindingJWS will reject it.
      }

      const challengeConsumed =
        jwsPurpose === 'recover-device'
          ? await consumeRecoverChallenge(expectedChallenge, userId)
          : await consumeRegisterChallenge(expectedChallenge, userId);
      if (!challengeConsumed) {
        return sendError(reply, 400, ERROR_CODES.INVALID_OR_EXPIRED_CHALLENGE);
      }

      try {
        await verifyDeviceBindingJWS(rootSignature, user.root_public_key, {
          purpose: jwsPurpose,
          userId,
          credentialId: registrationResponse.id,
          challenge: expectedChallenge,
        });
      } catch (err) {
        req.log.warn({ err }, 'root signature verification failed');
        return sendError(reply, 401, ERROR_CODES.INVALID_ROOT_SIGNATURE);
      }

      let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
      try {
        verification = await verifyRegistrationResponse({
          // biome-ignore lint/suspicious/noExplicitAny: shape is validated by Zod above
          response: registrationResponse as any,
          expectedChallenge,
          expectedOrigin: config.RP_ORIGIN,
          expectedRPID: config.RP_ID,
          requireUserVerification: true,
        });
      } catch (err) {
        req.log.warn({ err }, 'webauthn verification failed');
        return sendError(reply, 401, ERROR_CODES.ATTESTATION_VERIFICATION_FAILED);
      }
      if (!verification.verified || !verification.registrationInfo) {
        return sendError(reply, 401, ERROR_CODES.ATTESTATION_VERIFICATION_FAILED);
      }

      const { credential } = verification.registrationInfo;
      const credentialIdB64 = credential.id;
      const credentialPubKeyB64 = Buffer.from(credential.publicKey).toString('base64url');

      let device: Awaited<ReturnType<typeof insertDevice>>;
      try {
        device = await insertDevice({
          userId,
          credentialId: credentialIdB64,
          passkeyPublicKey: credentialPubKeyB64,
          signCount: credential.counter ?? 0,
          transports: (registrationResponse.response.transports ?? null) as string[] | null,
          deviceName: deviceName ?? null,
        });
      } catch (err) {
        if ((err as Record<string, unknown>).code === '23505') {
          // unique violation
          req.log.warn({ err }, 'credential already registered');
          return sendError(reply, 409, ERROR_CODES.ATTESTATION_VERIFICATION_FAILED);
        }
        throw err;
      }

      return reply.send({ deviceId: device.id, credentialId: credentialIdB64 });
    }
  );

  /**
   * POST /api/auth/challenge
   * Body: {} (empty)
   * Returns: { options }  (PublicKeyCredentialRequestOptionsJSON)
   *
   * Issues a discoverable-credential challenge. `allowCredentials` is empty
   * so the browser shows all authenticators including password manager
   * extensions, not just the platform authenticator.
   */
  app.post(
    ROUTES.AUTH.CHALLENGE,
    { config: { rateLimit: RATE_LIMITS.LOGIN } },
    async (_req, reply) => {
      const options = await generateAuthenticationOptions({
        rpID: config.RP_ID,
        userVerification: 'required',
        timeout: WEBAUTHN_TIMEOUT_MS,
      });

      const expiresAt = new Date(Date.now() + config.CHALLENGE_TTL_SECONDS * 1000);
      await insertLoginChallenge(options.challenge, expiresAt);

      return reply.send({ options });
    }
  );

  /**
   * POST /api/auth/login
   * Body: { assertion }  (assertion = AuthenticationResponseJSON)
   * Returns: { sessionChallenge, deviceId }
   *
   * Verifies the WebAuthn assertion against the stored login challenge,
   * advances the device's signature counter, then mints a one-shot
   * `sessionChallenge` for the SDK to bind a fresh session keypair to.
   */
  app.post(ROUTES.AUTH.LOGIN, { config: { rateLimit: RATE_LIMITS.LOGIN } }, async (req, reply) => {
    const parsed = loginBody.safeParse(req.body);
    if (!parsed.success) {
      return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsed.error.flatten());
    }
    const { assertion } = parsed.data;

    const device = await getDeviceByCredentialId(assertion.id);
    if (!device) {
      return sendError(reply, 404, ERROR_CODES.DEVICE_NOT_FOUND);
    }

    let expectedChallenge: string;
    try {
      expectedChallenge = extractChallenge(assertion);
    } catch (err) {
      req.log.warn({ err }, 'failed to extract challenge from login assertion');
      return sendError(reply, 400, ERROR_CODES.INVALID_INPUT);
    }

    const challengeConsumed = await consumeLoginChallenge(expectedChallenge);
    if (!challengeConsumed) {
      return sendError(reply, 400, ERROR_CODES.INVALID_OR_EXPIRED_CHALLENGE);
    }

    let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
    try {
      verification = await verifyAuthenticationResponse({
        // biome-ignore lint/suspicious/noExplicitAny: shape is validated by Zod above
        response: assertion as any,
        expectedChallenge,
        expectedOrigin: config.RP_ORIGIN, // string[] — all registered origins are valid
        expectedRPID: config.RP_ID,
        requireUserVerification: true,
        credential: {
          id: device.credential_id,
          publicKey: Buffer.from(device.passkey_public_key, 'base64url'),
          counter: Number(device.sign_count),
          transports: (device.transports ?? undefined) as
            // biome-ignore lint/suspicious/noExplicitAny: transport union widening
            any,
        },
      });
    } catch (err) {
      req.log.warn({ err }, 'webauthn authentication verification failed');
      return sendError(reply, 401, ERROR_CODES.ASSERTION_VERIFICATION_FAILED);
    }
    if (!verification.verified) {
      return sendError(reply, 401, ERROR_CODES.ASSERTION_VERIFICATION_FAILED);
    }

    await updateDeviceSignCount(device.id, verification.authenticationInfo.newCounter);

    const sessionChallenge = randomBytes(32).toString('base64url');
    const sessionChallengeExpiresAt = new Date(Date.now() + SESSION_CHALLENGE_TTL_MS);
    await insertSessionChallenge(sessionChallenge, device.id, sessionChallengeExpiresAt);

    return reply.send({ sessionChallenge, deviceId: device.id });
  });

  /**
   * POST /api/auth/session
   * Body: { sessionBinding }  (compact JWS, EdDSA)
   * Returns: { sessionId, expiresAt, userId }
   *
   * The JWS carries the session public key in its `jwk` protected header and
   * the server-issued `sessionChallenge` as a claim. We verify the signature
   * (proves PoP of the session privkey), atomically consume the challenge
   * (binds the session to the recent /login event for that device), then
   * persist the session row.
   */
  app.post(
    ROUTES.AUTH.SESSION,
    { config: { rateLimit: RATE_LIMITS.LOGIN } },
    async (req, reply) => {
      const parsed = sessionBody.safeParse(req.body);
      if (!parsed.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsed.error.flatten());
      }
      const { sessionBinding } = parsed.data;

      let verified: Awaited<ReturnType<typeof verifySessionBindingJWS>>;
      try {
        verified = await verifySessionBindingJWS(sessionBinding);
      } catch (err) {
        req.log.warn({ err }, 'session binding verification failed');
        return sendError(reply, 401, ERROR_CODES.INVALID_SESSION_BINDING);
      }

      const challenge = await consumeSessionChallenge(verified.payload.sessionChallenge);
      if (!challenge?.device_id) {
        return sendError(reply, 400, ERROR_CODES.INVALID_OR_EXPIRED_SESSION_CHALLENGE);
      }

      const device = await getDeviceById(challenge.device_id);
      if (!device) {
        return sendError(reply, 400, ERROR_CODES.DEVICE_NOT_FOUND);
      }

      const expiresAt = new Date(Date.now() + config.SESSION_TTL_SECONDS * 1000);
      const session = await insertSession({
        deviceId: challenge.device_id,
        sessionPublicKey: verified.sessionPublicKey,
        expiresAt,
      });

      return reply.send({
        sessionId: session.id,
        expiresAt: session.expires_at.getTime(),
        userId: device.user_id,
      });
    }
  );

  /**
   * POST /api/auth/recover
   * Body: { rootPublicKey }
   * Returns: { userId, options }  (same shape as /register)
   *
   * Looks up the existing user by root public key (only derivable from the
   * mnemonic) and returns WebAuthn registration options for a new device.
   * The actual root-key proof is submitted in the subsequent /register/device
   * call via a JWS with purpose='recover-device'.
   */
  app.post(
    ROUTES.AUTH.RECOVER,
    { config: { rateLimit: RATE_LIMITS.RECOVER } },
    async (req, reply) => {
      const parsed = recoverBody.safeParse(req.body);
      if (!parsed.success) {
        return sendError(reply, 400, ERROR_CODES.INVALID_INPUT, parsed.error.flatten());
      }
      const { rootPublicKey } = parsed.data;

      // Always run both operations in parallel regardless of whether the user
      // exists. This prevents timing-based enumeration: a missing key must not
      // return faster than a found one. The placeholder UUID is used only to
      // make buildRegistrationOptions do equivalent work; its output is discarded
      // when the user is not found.
      const [user, timingOptions] = await Promise.all([
        getUserByRootPublicKey(rootPublicKey),
        buildRegistrationOptions(randomUUID()),
      ]);

      const expiresAt = new Date(Date.now() + config.CHALLENGE_TTL_SECONDS * 1000);

      // Mirror the found user path's two serial operations so both branches
      // take the same time and can't be distinguished by response latency.
      // insertTimingRecoverChallenge uses user_id = NULL and expires_at = now(),
      // so the row is never consumable and is swept by the next GC run.
      if (!user) {
        const fakeOptions = await buildRegistrationOptions(randomUUID());
        await insertTimingRecoverChallenge(fakeOptions.challenge);
        return reply.send({ userId: randomUUID(), options: timingOptions });
      }

      const options = await buildRegistrationOptions(user.id);
      await insertRecoverChallenge(options.challenge, user.id, expiresAt);

      return reply.send({ userId: user.id, options });
    }
  );
}

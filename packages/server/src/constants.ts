import type { ServerErrorCode } from '@ghostid/shared';
import { PROTOCOL_VALIDATION, SERVER_ERROR_CODES, SESSION_AUTH_SCHEME } from '@ghostid/shared';

export type { ServerErrorCode };
export {
  PROTOCOL_VALIDATION as VALIDATION,
  SERVER_ERROR_CODES as ERROR_CODES,
  SESSION_AUTH_SCHEME,
};

export const WEBAUTHN_TIMEOUT_MS = 60_000;

export const RATE_LIMITS = {
  // Applied globally — authenticated / low-risk routes.
  DEFAULT: { max: 100, timeWindow: '1 minute' },
  // Account creation. An attacker can fill the DB or pre-register credentials
  // they don't control. Legitimate users need this at most a handful of times.
  REGISTER: { max: 10, timeWindow: '1 hour' },
  // Account recovery probes for existing users by root public key.
  // Tighter than register because a wrong key leaks whether a user exists.
  RECOVER: { max: 5, timeWindow: '1 hour' },
  // Login challenges and assertions. Allow room for multi-device users and
  // biometric retries without giving an attacker meaningful credential-stuffing
  // bandwidth.
  LOGIN: { max: 20, timeWindow: '15 minutes' },
} as const;

export const ERROR_MESSAGES: Record<ServerErrorCode, string> = {
  [SERVER_ERROR_CODES.INVALID_INPUT]: 'Request validation failed',
  [SERVER_ERROR_CODES.USER_NOT_FOUND]: 'User not found',
  [SERVER_ERROR_CODES.DEVICE_NOT_FOUND]: 'Device not found',
  [SERVER_ERROR_CODES.INVALID_OR_EXPIRED_CHALLENGE]: 'Challenge is invalid or has expired',
  [SERVER_ERROR_CODES.INVALID_ROOT_SIGNATURE]: 'Root key signature verification failed',
  [SERVER_ERROR_CODES.ATTESTATION_VERIFICATION_FAILED]: 'WebAuthn attestation verification failed',
  [SERVER_ERROR_CODES.ASSERTION_VERIFICATION_FAILED]: 'WebAuthn assertion verification failed',
  [SERVER_ERROR_CODES.INVALID_SESSION_BINDING]: 'Session binding verification failed',
  [SERVER_ERROR_CODES.INVALID_OR_EXPIRED_SESSION_CHALLENGE]:
    'Session challenge is invalid or has expired',
  [SERVER_ERROR_CODES.MISSING_SESSION_HEADERS]:
    'Required session authentication headers are missing',
  [SERVER_ERROR_CODES.INVALID_AUTHORIZATION_SCHEME]: 'Invalid authorization scheme',
  [SERVER_ERROR_CODES.MALFORMED_SESSION_HEADERS]: 'Session authentication headers are malformed',
  [SERVER_ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE]:
    'Request timestamp is outside the acceptable range',
  [SERVER_ERROR_CODES.SESSION_NOT_FOUND]: 'Session not found',
  [SERVER_ERROR_CODES.SESSION_REVOKED]: 'Session has been revoked',
  [SERVER_ERROR_CODES.SESSION_EXPIRED]: 'Session has expired',
  [SERVER_ERROR_CODES.INVALID_SESSION_SIGNATURE]: 'Session signature verification failed',
};

export const CHALLENGE_PURPOSE = {
  LOGIN: 'login',
  RECOVER: 'recover',
  REGISTER: 'register',
  SESSION: 'session',
} as const;

// How long the server-issued session challenge (POST /auth/session) stays valid
// after a successful /login. Tight by design, client should bind immediately.
export const SESSION_CHALLENGE_TTL_MS = 60_000;

export const ROUTES = {
  AUTH: {
    CHALLENGE: '/challenge',
    LOGIN: '/login',
    RECOVER: '/recover',
    REGISTER: '/register',
    REGISTER_DEVICE: '/register/device',
    SESSION: '/session',
  },
  DEVICES: {
    LIST: '/',
    REVOKE: '/:id',
  },
  SESSIONS: {
    LIST: '/',
    REVOKE: '/:id',
  },
  HEALTH: '/health',
} as const;

// Lowercase versions for Fastify header lookup — Fastify normalizes incoming
// header names to lowercase, so these must be lowercase to match.
export const AUTH_HEADERS = {
  AUTHORIZATION: 'authorization',
  SESSION_SIGNATURE: 'x-ghostid-signature',
  SESSION_TIMESTAMP: 'x-ghostid-timestamp',
} as const;

// Acceptable clock skew for per-request session signatures.
export const SESSION_SIG_TOLERANCE_SECONDS = 60;

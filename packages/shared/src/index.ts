export function canonicalJson(payload: unknown): string {
  if (payload === null || typeof payload !== 'object') {
    return JSON.stringify(payload);
  }

  if (Array.isArray(payload)) {
    return `[${payload.map(canonicalJson).join(',')}]`;
  }

  const pairs = Object.keys(payload as Record<string, unknown>)
    .sort()
    .map(
      key => `${JSON.stringify(key)}:${canonicalJson((payload as Record<string, unknown>)[key])}`
    );

  return `{${pairs.join(',')}}`;
}

// JWS type identifiers — provide cross-protocol isolation (RFC 8725 §3.11)
// so a token minted for one purpose cannot be misread as another.
export const ROOT_BINDING_TYP = 'ghostid-root-binding+jwt';
export const SESSION_BINDING_TYP = 'ghostid-session-binding+jwt';

// Root-key JWS purposes used in the `purpose` claim
export type RootPurpose = 'register-device' | 'recover-device' | 'revoke-device';

// Maximum age of a root-key JWS (register-device / recover-device / revoke-device).
// SDK sets exp = iat + ROOT_JWS_MAX_AGE_SECONDS; server enforces via maxTokenAge.
// The JWS is signed immediately before it is submitted (not when the challenge
// is issued), so a long CHALLENGE_TTL_SECONDS does not consume this budget. The
// realistic failure mode is client clock skew: jose applies zero clock tolerance
// to maxTokenAge, so a client clock more than ROOT_JWS_MAX_AGE_SECONDS behind the
// server rejects with INVALID_ROOT_SIGNATURE.
export const ROOT_JWS_MAX_AGE_SECONDS = 300;

// Maximum age of a session-binding JWS (POST /session).
// SDK sets exp = iat + SESSION_JWS_MAX_AGE_SECONDS; server enforces via maxTokenAge.
export const SESSION_JWS_MAX_AGE_SECONDS = 60;

// Authorization header scheme used for session-authenticated requests
export const SESSION_AUTH_SCHEME = 'GhostID-Session';

// Canonical HTTP header names as sent by the SDK.
// HTTP headers are case-insensitive; servers should compare lowercased.
export const GHOSTID_HEADERS = {
  AUTHORIZATION: 'Authorization',
  SESSION_NONCE: 'X-GhostID-Nonce',
  SESSION_SIGNATURE: 'X-GhostID-Signature',
  SESSION_TIMESTAMP: 'X-GhostID-Timestamp',
} as const;

// Validation limits that both the SDK (pre-send) and server (Zod schemas) enforce.
// Changing any value here requires a coordinated update to both packages.
export const PROTOCOL_VALIDATION = {
  MAX_DEVICE_NAME_LENGTH: 100,
  MIN_ROOT_PUBLIC_KEY_LENGTH: 16,
  MAX_ROOT_PUBLIC_KEY_LENGTH: 1024,
  MIN_ROOT_SIGNATURE_LENGTH: 16,
  MAX_ROOT_SIGNATURE_LENGTH: 1024,
  MIN_SESSION_BINDING_LENGTH: 64,
  MAX_SESSION_BINDING_LENGTH: 4096,
} as const;

// Error codes returned by the server in the `error` field of every error response.
// The SDK imports these to surface structured errors instead of opaque strings.
export const SERVER_ERROR_CODES = {
  ASSERTION_VERIFICATION_FAILED: 'assertion_verification_failed',
  ATTESTATION_VERIFICATION_FAILED: 'attestation_verification_failed',
  CREDENTIAL_ALREADY_REGISTERED: 'credential_already_registered',
  DEVICE_NOT_FOUND: 'device_not_found',
  INVALID_AUTHORIZATION_SCHEME: 'invalid_authorization_scheme',
  INVALID_INPUT: 'invalid_input',
  INVALID_OR_EXPIRED_CHALLENGE: 'invalid_or_expired_challenge',
  INVALID_OR_EXPIRED_SESSION_CHALLENGE: 'invalid_or_expired_session_challenge',
  INVALID_ROOT_SIGNATURE: 'invalid_root_signature',
  INVALID_SESSION_BINDING: 'invalid_session_binding',
  INVALID_SESSION_SIGNATURE: 'invalid_session_signature',
  MALFORMED_SESSION_HEADERS: 'malformed_session_headers',
  MISSING_SESSION_HEADERS: 'missing_session_headers',
  SESSION_EXPIRED: 'session_expired',
  SESSION_NOT_FOUND: 'session_not_found',
  SESSION_NONCE_USED: 'session_nonce_used',
  SESSION_REVOKED: 'session_revoked',
  SESSION_TIMESTAMP_OUT_OF_RANGE: 'session_timestamp_out_of_range',
  USER_NOT_FOUND: 'user_not_found',
} as const;

export type ServerErrorCode = (typeof SERVER_ERROR_CODES)[keyof typeof SERVER_ERROR_CODES];

// Wire-protocol error envelope: every server error response uses this shape.
// The SDK parses `error` to detect specific failure modes.
export interface ServerErrorResponse {
  error: ServerErrorCode;
  message: string;
  details?: unknown;
}

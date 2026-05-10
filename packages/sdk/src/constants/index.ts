/**
 * @file index.ts
 * Central constants for GhostID
 */

import { PROTOCOL_VALIDATION, SESSION_AUTH_SCHEME } from '@ghostid/shared';

export { SESSION_AUTH_SCHEME };

// ============================================================================
// HTTP Constants
// ============================================================================

export const HTTP_METHODS = {
  DELETE: 'DELETE',
  GET: 'GET',
  PATCH: 'PATCH',
  POST: 'POST',
  PUT: 'PUT',
} as const;

export const HTTP_HEADERS = {
  APPLICATION_JSON: 'application/json',
  AUTHORIZATION: 'Authorization',
  CONTENT_TYPE: 'Content-Type',
  SESSION_SIGNATURE: 'X-GhostID-Signature',
  SESSION_TIMESTAMP: 'X-GhostID-Timestamp',
} as const;

export const HTTP_STATUS = {
  // 2xx Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  // 4xx Client Errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  PAYMENT_REQUIRED: 402,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  NOT_ACCEPTABLE: 406,
  PROXY_AUTHENTICATION_REQUIRED: 407,
  REQUEST_TIMEOUT: 408,
  CONFLICT: 409,
  GONE: 410,
  LENGTH_REQUIRED: 411,
  PRECONDITION_FAILED: 412,
  PAYLOAD_TOO_LARGE: 413,
  URI_TOO_LONG: 414,
  UNSUPPORTED_MEDIA_TYPE: 415,
  RANGE_NOT_SATISFIABLE: 416,
  EXPECTATION_FAILED: 417,
  IM_A_TEAPOT: 418,
  MISDIRECTED_REQUEST: 421,
  UNPROCESSABLE_ENTITY: 422,
  LOCKED: 423,
  FAILED_DEPENDENCY: 424,
  TOO_EARLY: 425,
  UPGRADE_REQUIRED: 426,
  PRECONDITION_REQUIRED: 428,
  TOO_MANY_REQUESTS: 429,
  REQUEST_HEADER_FIELDS_TOO_LARGE: 431,
  UNAVAILABLE_FOR_LEGAL_REASONS: 451,

  // 5xx Server Errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
  HTTP_VERSION_NOT_SUPPORTED: 505,
  VARIANT_ALSO_NEGOTIATES: 506,
  INSUFFICIENT_STORAGE: 507,
  LOOP_DETECTED: 508,
  NOT_EXTENDED: 510,
  NETWORK_AUTHENTICATION_REQUIRED: 511,
} as const;

// Status code ranges for easier checking
export const HTTP_STATUS_RANGES = {
  CLIENT_ERROR_START: 400,
  CLIENT_ERROR_END: 499,
  SERVER_ERROR_START: 500,
  SERVER_ERROR_END: 599,
} as const;

// ============================================================================
// API Endpoints
// ============================================================================

export const API_ENDPOINTS = {
  AUTH: {
    CHALLENGE: '/api/auth/challenge',
    LOGIN: '/api/auth/login',
    REGISTER: '/api/auth/register',
    REGISTER_DEVICE: '/api/auth/register/device',
    RECOVER: '/api/auth/recover',
    SESSION: '/api/auth/session',
    SESSION_RESTORE: '/api/auth/session/restore',
  },
  DEVICES: {
    LIST: '/api/devices',
    REVOKE: '/api/devices',
  },
  SESSIONS: {
    LIST: '/api/sessions',
    REVOKE: '/api/sessions',
  },
} as const;

// ============================================================================
// Timeout and Retry Constants
// ============================================================================

export const TIMEOUTS = {
  DEFAULT_REQUEST: 30000, // 30 seconds
  DEFAULT_RETRY_DELAY: 1000, // 1 second
  MAX_RETRY_DELAY: 5000, // 5 seconds
} as const;

export const RETRY = {
  DEFAULT_ATTEMPTS: 3,
  EXPONENTIAL_BACKOFF_BASE: 2,
} as const;

// ============================================================================
// Cryptographic Constants
// ============================================================================

export const CRYPTO = {
  // Key derivation context for root keys
  ROOT_KEY_CONTEXT: 'ghostid-root-sign',

  // Key sizes
  NONCE_SIZE: 32,
  HASH_SIZE: 32,
  SIGNING_KEY_SIZE: 32,

  // BIP39
  MNEMONIC_STRENGTH: 128, // 12 words
} as const;

// ============================================================================
// WebAuthn Constants
// ============================================================================

export const WEBAUTHN = {
  ALGORITHM: -7, // ES256
  ATTESTATION: 'none',
  CREDENTIAL_TYPE: 'public-key',
  TIMEOUT: 60000, // 60 seconds
  USER_VERIFICATION: 'preferred',
} as const;

// ============================================================================
// Session Constants
// ============================================================================

export const SESSION = {
  DEFAULT_EXPIRY_HOURS: 24,
  MAX_EXPIRY_HOURS: 168, // 1 week
} as const;

// ============================================================================
// Device Name Detection
// ============================================================================

export const UA_HINTS: Array<[string, string]> = [
  ['iPhone', 'iPhone'],
  ['iPad', 'iPad'],
  ['Android', 'Android Device'],
  ['Mac', 'Mac'],
  ['Windows', 'Windows PC'],
  ['Linux', 'Linux PC'],
];

// ============================================================================
// Error Messages
// ============================================================================

export const ERROR_MESSAGES = {
  // Core / lifecycle
  NOT_INITIALIZED: 'GhostID not initialized: call init() first',
  NO_ACTIVE_SESSION: 'No active session: login() first',
  SESSION_EXPIRED: 'Session expired: please login again',

  // Crypto / keys
  INVALID_MNEMONIC: 'Invalid BIP39 mnemonic phrase provided',
  KEY_DERIVATION_FAILED: 'Failed to derive root keys from BIP39 mnemonic',
  SIGNING_FAILED: 'Failed to sign request payload',
  INVALID_SIGNING_PAYLOAD: 'Invalid payload for signing',
  INVALID_SIGNING_KEY: 'Invalid private key for signing',
  SIGNATURE_VERIFICATION_FAILED: 'Signature verification failed',
  CRYPTO_INIT_FAILED: 'Failed to initialize cryptographic library',

  // WebAuthn / passkeys
  WEB_AUTHN_NOT_SUPPORTED: 'WebAuthn not available in this environment',
  PASSKEY_CREATION_CANCELLED: 'Failed to create passkey: user may have cancelled',
  PASSKEY_ASSERTION_CANCELLED:
    'Failed to get passkey assertion: user may have cancelled or no credentials found',
  PASSKEY_CREATION_FAILED: 'Passkey creation failed',
  PASSKEY_ASSERTION_FAILED: 'Passkey authentication failed',

  // API client configuration
  INVALID_BASE_URL: 'Invalid baseUrl provided',
  INVALID_BASE_URL_FORMAT: 'Invalid URL format for baseUrl',
  BASE_URL_REQUIRES_HTTPS: 'baseUrl must use HTTPS (HTTP is only permitted for localhost)',
  INVALID_TIMEOUT: 'Invalid timeout value',
  INVALID_RETRY_ATTEMPTS: 'Invalid retry attempts value',

  // Request validation
  INVALID_HTTP_METHOD: 'Invalid HTTP method',
  INVALID_PATH: 'Invalid path provided',
  PATH_TOO_LONG: 'Path too long',
  INVALID_PATH_FORMAT: 'Invalid path format',
  INVALID_HEADER_NAME: 'Invalid header name',
  FORBIDDEN_HEADER: 'Forbidden header',
  INVALID_HEADER_VALUE: 'Invalid header value for',

  // Request / response handling
  FAILED_TO_SERIALIZE: 'Failed to serialize request data',
  REQUEST_BODY_TOO_LARGE: 'Request body too large',
  FAILED_TO_PARSE_RESPONSE: 'Failed to parse response JSON',
  REQUEST_TIMED_OUT: 'Request timed out',

  // Auth
  INVALID_REGISTRATION_RESPONSE: 'Invalid registrationResponse provided',
  INVALID_ASSERTION_RESPONSE: 'Invalid assertion provided',

  // Misc
  API_REQUEST_FAILED: 'API request failed after multiple retries',
  CHALLENGE_EXPIRED: 'Challenge has expired',
  DEVICE_NOT_FOUND: 'Device not found',
  INVALID_CHALLENGE: 'Invalid challenge provided',
  USER_NOT_FOUND: 'User not found',
} as const;

// ============================================================================
// Validation Constants
// ============================================================================

export const VALIDATION = {
  // SDK-only fields
  MIN_CHALLENGE_LENGTH: 16,
  MAX_CHALLENGE_LENGTH: 64,
  MIN_DEVICE_NAME_LENGTH: 1,
  MIN_MNEMONIC_WORDS: 12,
  MAX_MNEMONIC_WORDS: 24,
  MAX_DEVICE_ID_LENGTH: 256,
  MAX_SESSION_TOKEN_LENGTH: 512,
  MAX_STRING_LENGTH: 2000,
  // Aliases kept for existing callers (root public key and root JWS)
  MAX_PUBLIC_KEY_LENGTH: PROTOCOL_VALIDATION.MAX_ROOT_PUBLIC_KEY_LENGTH,
  MAX_SIGNATURE_LENGTH: PROTOCOL_VALIDATION.MAX_ROOT_SIGNATURE_LENGTH,
  // Protocol-shared limits (from @ghostid/shared — single source of truth)
  ...PROTOCOL_VALIDATION,
} as const;

// Security constants
export const SECURITY = {
  ALLOWED_HTTP_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const,
  MAX_HEADER_VALUE_LENGTH: 4096, // Max header value length
  MAX_HEADER_NAME_LENGTH: 256, // Max header name length
  MAX_PATH_LENGTH: 2048, // Max URL path length
  MAX_REQUEST_BODY_SIZE: 1024 * 1024, // 1MB max request body
  // Headers the client must never set manually — browser/runtime controls these,
  // or they are HTTP/1.1 connection-level fields that must not be overridden.
  // Note: 'authorization' is intentionally NOT listed here; the SDK sends it for session auth.
  FORBIDDEN_HEADERS: [
    'connection',
    'content-length',
    'cookie',
    'host',
    'origin',
    'referer',
    'set-cookie',
    'transfer-encoding',
    'upgrade',
    'x-forwarded-for',
    'x-real-ip',
  ] as const,
} as const;

// ============================================================================
// Type Exports
// ============================================================================

export type ApiEndpoint = (typeof API_ENDPOINTS)[keyof typeof API_ENDPOINTS];
export type CryptoConfig = (typeof CRYPTO)[keyof typeof CRYPTO];
export type ErrorMessage = (typeof ERROR_MESSAGES)[keyof typeof ERROR_MESSAGES];
export type HttpHeader = (typeof HTTP_HEADERS)[keyof typeof HTTP_HEADERS];
export type HttpMethod = (typeof HTTP_METHODS)[keyof typeof HTTP_METHODS];
export type HttpStatus = (typeof HTTP_STATUS)[keyof typeof HTTP_STATUS];
export type HttpStatusRange = (typeof HTTP_STATUS_RANGES)[keyof typeof HTTP_STATUS_RANGES];
export type RetryConfig = (typeof RETRY)[keyof typeof RETRY];
export type SessionConfig = (typeof SESSION)[keyof typeof SESSION];
export type Timeout = (typeof TIMEOUTS)[keyof typeof TIMEOUTS];
export type ValidationRule = (typeof VALIDATION)[keyof typeof VALIDATION];
export type WebAuthnConfig = (typeof WEBAUTHN)[keyof typeof WEBAUTHN];

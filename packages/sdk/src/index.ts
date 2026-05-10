export { createApiClient } from './api/client';
export { createPasskey, getPasskeyAssertion, isWebAuthnSupported } from './auth/passkey';
export {
  API_ENDPOINTS,
  CRYPTO,
  ERROR_MESSAGES,
  HTTP_HEADERS,
  HTTP_METHODS,
  HTTP_STATUS,
  HTTP_STATUS_RANGES,
  RETRY,
  SESSION,
  TIMEOUTS,
  VALIDATION,
  WEBAUTHN,
} from './constants';
export {
  base64UrlToBuffer,
  bufferToBase64Url,
  constantTimeEqual,
  fromBase64,
  generateMnemonic,
  generateNonce,
  generateSessionSigningKeypair,
  hash,
  secureWipe,
  sign,
  stringToBytes,
  toBase64,
  validateMnemonic,
  verify,
} from './core/crypto';
export { ErrorCodes, GhostIDError } from './core/errors';
export { GhostID } from './ghostid';
export type {
  // API Client types
  ApiClientOptions,
  ApiError,
  ApiResponse,
  CreateIdentityResult,
  CreateSessionRequest,
  CreateSessionResponse,
  DeviceInfo,
  // Error types
  ErrorCode,
  // Passkey types
  FormattedCreatePasskeyResponse,
  FormattedGetPasskeyAssertionResponse,
  GetDevicesResponse,
  // GhostID SDK types
  GhostIDOptions,
  // Core types
  KeyPair,
  LoginRequest,
  LoginResponse,
  LoginResult,
  RecoverAccountRequest,
  RecoverAccountResponse,
  RecoverIdentityResult,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  RegisterUserRequest,
  RegisterUserResponse,
  RequestChallengeResponse,
  RevokeDeviceRequest,
  RootKeySet,
  SessionInfo,
  SessionListItem,
} from './types';

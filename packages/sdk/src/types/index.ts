/**
 * @file index.ts
 * Central type definitions for GhostID
 */

// ============================================================================
// DOM API Types
// ============================================================================

export interface CredentialCreationOptions {
  publicKey?: PublicKeyCredentialCreationOptions;
}

export interface CredentialRequestOptions {
  publicKey?: PublicKeyCredentialRequestOptions;
}

export interface Credential {
  id: string;
  type: string;
}

export interface PublicKeyCredentialRpEntity {
  name: string;
  id?: string;
}

export interface PublicKeyCredentialUserEntity {
  id: ArrayBuffer;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialParameters {
  type: PublicKeyCredentialType;
  alg: number;
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  userVerification?: UserVerificationRequirement;
}

export type PublicKeyCredentialType = 'public-key';
export type AuthenticatorAttachment = 'platform' | 'cross-platform';
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';
export type AttestationConveyancePreference = 'none' | 'indirect' | 'direct';

export interface PublicKeyCredential extends Credential {
  rawId: ArrayBuffer;
  response: AuthenticatorResponse;
}

export interface AuthenticatorAttestationResponse extends AuthenticatorResponse {
  attestationObject: ArrayBuffer;
}

export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer | null;
}

export interface AuthenticatorResponse {
  clientDataJSON: ArrayBuffer;
}

// ============================================================================
// Core Types
// ============================================================================

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

export interface RootKeySet {
  signing: KeyPair;
  version: number;
  createdAt: number;
}

// ============================================================================
// Passkey Types
// ============================================================================

/**
 * Shape compatible with `@simplewebauthn/server`'s `RegistrationResponseJSON`.
 */
export interface FormattedCreatePasskeyResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment?: AuthenticatorAttachment;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: AuthenticatorTransport[];
  };
}

/**
 * Shape compatible with `@simplewebauthn/server`'s `AuthenticationResponseJSON`.
 */
export interface FormattedGetPasskeyAssertionResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment?: AuthenticatorAttachment;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
}

// ============================================================================
// API Client Types
// ============================================================================

export interface ApiClientOptions {
  baseUrl: string;
  timeout?: number;
  retryAttempts?: number;
  onUnauthorized?: (method: string, path: string) => Promise<Record<string, string>>;
}

export interface ApiResponse<T = Record<string, unknown>> {
  data: T;
  status: number;
  statusText: string;
}

export interface ApiError {
  message: string;
  code: string;
  status?: number;
}

export interface RegisterUserRequest extends Record<string, unknown> {
  rootPublicKey: string;
}

/**
 * `options` is a `PublicKeyCredentialCreationOptionsJSON` produced by
 * `@simplewebauthn/server` on the backend; pass straight to `createPasskey`.
 */
export interface RegisterUserResponse extends Record<string, unknown> {
  userId: string;
  options: Record<string, unknown>;
}

export interface RegisterDeviceRequest extends Record<string, unknown> {
  userId: string;
  /** RegistrationResponseJSON shape returned by `createPasskey`. */
  registrationResponse: FormattedCreatePasskeyResponse;
  /** Ed25519 signature over canonical `register-device|{userId}|{credentialId}|{challenge}`. */
  rootSignature: string;
  deviceName?: string;
}

export interface RegisterDeviceResponse extends Record<string, unknown> {
  deviceId: string;
  credentialId: string;
}

export interface LoginRequest extends Record<string, unknown> {
  /** AuthenticationResponseJSON shape returned by `getPasskeyAssertion`. */
  assertion: FormattedGetPasskeyAssertionResponse;
}

export interface LoginResponse extends Record<string, unknown> {
  /** Server-issued nonce; client signs it with a fresh session keypair. */
  sessionChallenge: string;
  /** Device ID resolved server-side from the assertion's credential ID. */
  deviceId: string;
}

export interface RequestChallengeResponse extends Record<string, unknown> {
  /** PublicKeyCredentialRequestOptionsJSON; pass to `getPasskeyAssertion`. */
  options: Record<string, unknown>;
}

export interface CreateSessionRequest extends Record<string, unknown> {
  /** Compact JWS (EdDSA) carrying the session pubkey in the JWK header. */
  sessionBinding: string;
}

export interface CreateSessionResponse extends Record<string, unknown> {
  sessionId: string;
  expiresAt: number;
  userId: string;
}

export interface DeviceInfo extends Record<string, unknown> {
  id: string;
  credentialId: string;
  deviceName: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface GetDevicesResponse extends Record<string, unknown> {
  devices: DeviceInfo[];
}

export interface RevokeDeviceRequest extends Record<string, unknown> {
  rootSignature: string;
}

export interface SessionListItem extends Record<string, unknown> {
  id: string;
  deviceId: string;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: number;
  isCurrent: boolean;
}

export interface RecoverAccountRequest extends Record<string, unknown> {
  rootPublicKey: string;
}

export interface RecoverAccountResponse extends Record<string, unknown> {
  userId: string;
  options: Record<string, unknown>;
}

export interface RestoreSessionResponse extends Record<string, unknown> {
  sessionId: string;
  userId: string;
  deviceId: string;
  expiresAt: number;
}

// ============================================================================
// GhostID SDK Types
// ============================================================================

export interface GhostIDOptions {
  backendUrl: string;
  /** Human-readable name for newly registered devices. */
  defaultDeviceName?: string;
  apiClientOptions?: Partial<ApiClientOptions>;
}

export interface SessionInfo {
  sessionId: string;
  userId: string;
  deviceId: string;
  expiresAt: number;
}

export interface CreateIdentityResult {
  mnemonic: string[];
  userId: string;
  deviceId: string;
}

export interface RecoverIdentityResult {
  userId: string;
  deviceId: string;
}

// ============================================================================
// Error Types
// ============================================================================

export const ErrorCodes = {
  NOT_INITIALIZED: 'NOT_INITIALIZED',
  INVALID_INPUT: 'INVALID_INPUT',
  CRYPTOGRAPHY_ERROR: 'CRYPTOGRAPHY_ERROR',
  NO_KEYS: 'NO_KEYS',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  STORAGE_ERROR: 'STORAGE_ERROR',
  INVALID_CHALLENGE: 'INVALID_CHALLENGE',
  EXPIRED_CHALLENGE: 'EXPIRED_CHALLENGE',
  API_ERROR: 'API_ERROR',
  INVALID_STATE: 'INVALID_STATE',
  CLOCK_SKEW: 'CLOCK_SKEW',
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

/**
 * @file ghostid.ts
 * Main GhostID SDK class. Three-layer identity model:
 *   1. Root identity (BIP39 mnemonic and Ed25519) - recovery and high-stakes ops.
 *   2. Device identity (WebAuthn passkey) - daily auth.
 *   3. Session identity (ephemeral Ed25519) - silent request signing.
 *
 * The SDK persists nothing. Session identity lives in an httpOnly cookie set by
 * the server; the session private key lives only in memory. On page reload,
 * call restoreSession() to rebind a fresh keypair to the existing session.
 *
 * Session identity: ephemeral Ed25519 keypair generated via WebCrypto. The
 * private key is non-extractable — its bytes never enter the JS heap. Root key
 * bytes are zeroed after use as a best-effort measure; JavaScript cannot
 * guarantee secure erasure (GC may copy buffers before they are zeroed).
 */

import { ApiClient, createApiClient } from './api/client';
import { signDeviceBindingJWS } from './api/root-jws';
import { signSessionBindingJWS } from './api/session-jws';
import {
  creationOptionsFromServer,
  extractChallenge,
  requestOptionsFromServer,
} from './auth/options';
import { createPasskey, getPasskeyAssertion, isWebAuthnSupported } from './auth/passkey';
import { ERROR_MESSAGES, HTTP_HEADERS, SESSION_AUTH_SCHEME, UA_HINTS } from './constants';
import {
  deriveRootKeysFromMnemonic,
  generateMnemonic,
  generateSessionSigningKeypair,
  toBase64,
} from './core/crypto';
import { ErrorCodes, GhostIDError } from './core/errors';
import type {
  CreateIdentityResult,
  DeviceInfo,
  GhostIDOptions,
  LoginResult,
  RecoverIdentityResult,
  SessionInfo,
  SessionListItem,
} from './types';

interface ActiveSession {
  sessionId: string;
  userId: string;
  deviceId: string;
  expiresAt: number;
  sessionPrivateKey: CryptoKey;
}

export class GhostID {
  private readonly apiClient: ApiClient;
  private readonly defaultDeviceName?: string;
  private initialized = false;
  private session: ActiveSession | null = null;

  constructor(options: GhostIDOptions) {
    this.apiClient = createApiClient({
      baseUrl: options.backendUrl,
      ...options.apiClientOptions,
    });
    this.defaultDeviceName = options.defaultDeviceName;
  }

  init(): void {
    this.initialized = true;
  }

  async restoreSession(): Promise<void> {
    this.ensureInitialized();
    const sessionKeyPair = await generateSessionSigningKeypair();
    try {
      const nonce = crypto.randomUUID();
      const sessionBinding = await signSessionBindingJWS(
        { sessionChallenge: nonce },
        sessionKeyPair.privateKey,
        sessionKeyPair.publicKey
      );
      const response = await this.apiClient.auth.restoreSession(sessionBinding);
      this.session = {
        sessionId: response.sessionId,
        userId: response.userId,
        deviceId: response.deviceId,
        expiresAt: response.expiresAt,
        sessionPrivateKey: sessionKeyPair.privateKey,
      };
    } catch {
      throw new GhostIDError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new GhostIDError(ERROR_MESSAGES.NOT_INITIALIZED, ErrorCodes.NOT_INITIALIZED);
    }
  }

  /**
   * Creates a new identity end-to-end:
   *   1. Generate mnemonic and root keys.
   *   2. POST /register with rootPublicKey -> server returns userId and WebAuthn options.
   *   3. Browser produces a passkey credential.
   *   4. SDK signs `register-device|userId|credentialId|challenge` with root key.
   *   5. POST /register/device with the registration response and root signature.
   *
   * Caller must persist the returned mnemonic offline (it is the only recovery path).
   * userId and deviceId are persisted automatically by the SDK.
   */
  async createIdentity(): Promise<CreateIdentityResult> {
    this.ensureInitialized();
    if (!isWebAuthnSupported()) {
      throw new GhostIDError(ERROR_MESSAGES.WEB_AUTHN_NOT_SUPPORTED, ErrorCodes.INVALID_INPUT);
    }

    const mnemonic = generateMnemonic();
    const rootKeySet = await deriveRootKeysFromMnemonic(mnemonic);
    const rootPublicKey = toBase64(rootKeySet.signing.publicKey);

    try {
      const registerResponse = await this.apiClient.auth.registerUser({ rootPublicKey });
      const { userId, options } = registerResponse;

      const passkeyOptions = creationOptionsFromServer(options);
      const passkeyResponse = await createPasskey(passkeyOptions);

      const challengeB64Url = extractChallenge(passkeyOptions);
      const rootSignature = await signDeviceBindingJWS(
        {
          purpose: 'register-device',
          userId,
          credentialId: passkeyResponse.id,
          challenge: challengeB64Url,
        },
        rootKeySet.signing.privateKey,
        rootKeySet.signing.publicKey
      );

      const deviceResponse = await this.apiClient.auth.registerDevice({
        userId,
        registrationResponse: passkeyResponse,
        rootSignature,
        deviceName: this.defaultDeviceName ?? this.guessDeviceName(),
      });

      return { mnemonic, userId, deviceId: deviceResponse.deviceId };
    } finally {
      rootKeySet.signing.privateKey.fill(0);
    }
  }

  /**
   * Authenticates with a passkey and creates a session:
   *   1. POST /challenge → server returns discoverable-credential options
   *      (empty allowCredentials so the browser shows all authenticators,
   *      including password manager extensions).
   *   2. Browser produces an assertion.
   *   3. POST /login with the assertion → server looks up the device by
   *      credential ID, verifies, returns `{ sessionChallenge, deviceId }`.
   *   4. SDK generates an ephemeral session keypair, signs a session-binding
   *      JWS (session pubkey in the JWK header and sessionChallenge claim).
   *   5. POST /session → server verifies PoP, persists the session row,
   *      returns `{ sessionId, expiresAt }`.
   */
  async login(): Promise<LoginResult> {
    this.ensureInitialized();

    const challengeResponse = await this.apiClient.auth.requestChallenge();
    const assertionOptions = requestOptionsFromServer(challengeResponse.options);
    const assertion = await getPasskeyAssertion(assertionOptions);

    const loginResponse = await this.apiClient.auth.login({ assertion });

    const sessionKeyPair = await generateSessionSigningKeypair();
    const sessionBinding = await signSessionBindingJWS(
      { sessionChallenge: loginResponse.sessionChallenge },
      sessionKeyPair.privateKey,
      sessionKeyPair.publicKey
    );
    const sessionResponse = await this.apiClient.auth.createSession({ sessionBinding });

    this.session = {
      sessionId: sessionResponse.sessionId,
      userId: sessionResponse.userId,
      deviceId: loginResponse.deviceId,
      expiresAt: sessionResponse.expiresAt,
      sessionPrivateKey: sessionKeyPair.privateKey,
    };

    return { sessionId: sessionResponse.sessionId, expiresAt: sessionResponse.expiresAt };
  }

  /**
   * Recovers an account using the mnemonic. Server looks up the user by the
   * derived root public key and issues a registration challenge for a new
   * device. The returned userId matches the original; the deviceId is new.
   */
  async recoverIdentity(mnemonic: string): Promise<RecoverIdentityResult> {
    this.ensureInitialized();
    if (!isWebAuthnSupported()) {
      throw new GhostIDError(ERROR_MESSAGES.WEB_AUTHN_NOT_SUPPORTED, ErrorCodes.INVALID_INPUT);
    }

    const rootKeySet = await deriveRootKeysFromMnemonic(mnemonic);
    const rootPublicKey = toBase64(rootKeySet.signing.publicKey);

    try {
      const recoverResponse = await this.apiClient.auth.recoverAccount({ rootPublicKey });
      const { userId, options } = recoverResponse;

      const passkeyOptions = creationOptionsFromServer(options);
      const passkeyResponse = await createPasskey(passkeyOptions);
      const challengeB64Url = extractChallenge(passkeyOptions);
      const rootSignature = await signDeviceBindingJWS(
        {
          purpose: 'recover-device',
          userId,
          credentialId: passkeyResponse.id,
          challenge: challengeB64Url,
        },
        rootKeySet.signing.privateKey,
        rootKeySet.signing.publicKey
      );

      const deviceResponse = await this.apiClient.auth.registerDevice({
        userId,
        registrationResponse: passkeyResponse,
        rootSignature,
        deviceName: this.defaultDeviceName ?? this.guessDeviceName(),
      });

      return { userId, deviceId: deviceResponse.deviceId };
    } finally {
      rootKeySet.signing.privateKey.fill(0);
    }
  }

  /** Signs a payload with the in-memory session key. Throws if no session. */
  async signWithSessionKey(payload: Record<string, unknown>): Promise<string> {
    this.ensureInitialized();
    if (!this.session) {
      throw new GhostIDError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    if (Date.now() > this.session.expiresAt) {
      this.session = null;
      throw new GhostIDError(ERROR_MESSAGES.SESSION_EXPIRED, ErrorCodes.EXPIRED_CHALLENGE);
    }
    return ApiClient.signRequest(payload, this.session.sessionPrivateKey);
  }

  /**
   * Returns headers that authenticate requests to the integrator's own backend.
   * The GhostID server's `requireSession` middleware validates these headers.
   *
   * Every call generates a fresh timestamp and signature - do not cache the result.
   */
  async getSessionHeaders(): Promise<Record<string, string>> {
    this.ensureInitialized();
    if (!this.session) {
      throw new GhostIDError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const signature = await this.signWithSessionKey({ sessionId, iat });
    return {
      [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${sessionId}`,
      [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
      [HTTP_HEADERS.SESSION_SIGNATURE]: signature,
    };
  }

  async logout(): Promise<void> {
    this.ensureInitialized();
    if (!this.session) {
      return;
    }
    const { sessionId, sessionPrivateKey } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const signature = await ApiClient.signRequest({ sessionId, iat }, sessionPrivateKey);
    await this.apiClient.sessions.revokeSession(sessionId, sessionId, iat, signature);
    this.session = null;
  }

  async getDevices(): Promise<DeviceInfo[]> {
    this.ensureInitialized();
    if (!this.session) {
      throw new GhostIDError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const signature = await this.signWithSessionKey({ sessionId, iat });
    const response = await this.apiClient.devices.getDevices(sessionId, iat, signature);
    return response.devices;
  }

  /**
   * Revokes a device using the root key derived from the mnemonic.
   * `userId` and `credentialId` are available from `createIdentity`, `recoverIdentity`,
   * or a prior `getDevices()` call.
   */
  async revokeDevice(
    deviceId: string,
    mnemonic: string,
    userId: string,
    credentialId: string
  ): Promise<void> {
    this.ensureInitialized();

    const rootKeySet = await deriveRootKeysFromMnemonic(mnemonic);
    try {
      const rootSignature = await signDeviceBindingJWS(
        { purpose: 'revoke-device', userId, credentialId, challenge: deviceId },
        rootKeySet.signing.privateKey,
        rootKeySet.signing.publicKey
      );
      await this.apiClient.devices.revokeDevice(deviceId, rootSignature);
    } finally {
      rootKeySet.signing.privateKey.fill(0);
    }
  }

  async getSessions(): Promise<SessionListItem[]> {
    this.ensureInitialized();
    if (!this.session) {
      throw new GhostIDError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const signature = await this.signWithSessionKey({ sessionId, iat });
    const response = await this.apiClient.sessions.getSessions(sessionId, iat, signature);
    return response.sessions;
  }

  async revokeSession(targetSessionId: string): Promise<void> {
    this.ensureInitialized();
    if (!this.session) {
      throw new GhostIDError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const signature = await this.signWithSessionKey({ sessionId, iat });
    await this.apiClient.sessions.revokeSession(targetSessionId, sessionId, iat, signature);
    if (targetSessionId === sessionId) {
      this.session = null;
    }
  }

  /**
   * Returns information about the active session, or null if logged out.
   * The session private key is intentionally not exposed.
   */
  getSession(): SessionInfo | null {
    if (!this.session) return null;
    return {
      sessionId: this.session.sessionId,
      userId: this.session.userId,
      deviceId: this.session.deviceId,
      expiresAt: this.session.expiresAt,
    };
  }

  destroy(): void {
    this.session = null;
    this.initialized = false;
  }

  private guessDeviceName(): string {
    if (typeof navigator === 'undefined') {
      return 'Unknown Device';
    }
    const ua = navigator.userAgent;
    const match = UA_HINTS.find(([token]) => ua.includes(token));
    return match ? match[1] : 'Unknown Device';
  }
}

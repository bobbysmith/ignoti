/**
 * Main Ignoti SDK class. Three-layer identity model:
 *   1. Root identity (BIP39 mnemonic and Ed25519) - recovery and high-stakes ops.
 *   2. Device identity (WebAuthn passkey) - daily auth.
 *   3. Session identity (ephemeral Ed25519) - silent request signing.
 *
 * Session identity lives in an httpOnly cookie set by the server plus a session
 * keypair generated via WebCrypto at login. The keypair is kept in IndexedDB so
 * that restoreSession() can resume the session after a page reload; a session
 * keeps the same key for its whole life. The SDK persists nothing else.
 *
 * The session private key is non-extractable - its bytes never enter the JS
 * heap, in memory or in storage. Root key
 * bytes are zeroed after use as a best-effort measure; JavaScript cannot
 * guarantee secure erasure (GC may copy buffers before they are zeroed).
 */

import { canonicalRequestUrl } from '@ignoti/shared';
import { ApiClient, createApiClient } from './api/client';
import { signDeviceBindingJWS } from './api/root-jws';
import { signSessionBindingJWS } from './api/session-jws';
import {
  creationOptionsFromServer,
  extractChallenge,
  requestOptionsFromServer,
} from './auth/options';
import { createPasskey, getPasskeyAssertion, isWebAuthnSupported } from './auth/passkey';
import {
  API_ENDPOINTS,
  ERROR_MESSAGES,
  HTTP_HEADERS,
  RETRY,
  SESSION_AUTH_SCHEME,
  UA_HINTS,
} from './constants';
import {
  deriveRootKeysFromMnemonic,
  generateMnemonic,
  generateSessionSigningKeypair,
  sha256Base64Url,
  toBase64,
} from './core/crypto';
import { ErrorCodes, IgnotiError } from './core/errors';
import { createSessionKeyStore, type SessionKeyStore } from './core/session-key-store';
import type {
  CreateIdentityResult,
  DeviceInfo,
  IgnotiOptions,
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
  sessionPublicKey: CryptoKey;
}

export class Ignoti {
  private readonly apiClient: ApiClient;
  private readonly backendUrl: string;
  private readonly defaultDeviceName?: string;
  private initialized = false;
  private session: ActiveSession | null = null;
  private readonly sessionKeys: SessionKeyStore;
  private restorePromise: Promise<void> | null = null;
  private restoreFailures = 0;
  private sessionChangeCallback: ((session: SessionInfo | null) => void) | null = null;

  constructor(options: IgnotiOptions) {
    this.apiClient = createApiClient({
      baseUrl: options.backendUrl,
      ...options.apiClientOptions,
      onUnauthorized: (m, p) => this.handleUnauthorized(m, p),
    });
    this.backendUrl = options.backendUrl.replace(/\/$/, '');
    this.sessionKeys = createSessionKeyStore(this.backendUrl);
    this.defaultDeviceName = options.defaultDeviceName;
  }

  /** `htu` for a request to the Ignoti server. */
  private backendHtu(path: string): string {
    return canonicalRequestUrl(`${this.backendUrl}${path}`);
  }

  /** `htu` for an integrator request. Relative URLs resolve against the page URL. */
  private resolveHtu(url: string): string {
    try {
      const base = typeof location !== 'undefined' ? location.href : undefined;
      return canonicalRequestUrl(new URL(url, base).href);
    } catch {
      throw new IgnotiError(ERROR_MESSAGES.INVALID_REQUEST_URL, ErrorCodes.INVALID_INPUT);
    }
  }

  /**
   * Automatic-recovery restore. Applies the failure gate: after
   * RETRY.MAX_RESTORE_FAILURES consecutive failures no new attempt starts
   * until a restore or login succeeds. Joins an in-flight attempt if one exists.
   */
  private async restoreOnce(): Promise<void> {
    if (!this.restorePromise && this.restoreFailures >= RETRY.MAX_RESTORE_FAILURES) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    await this.dedupedRestore();
  }

  /**
   * Single-flights the restore so concurrent callers on this instance (a
   * StrictMode double-invoke, or an automatic recovery overlapping an explicit
   * restoreSession()) share one attempt and rotate the restore cookie once.
   * Failure count increments once per attempt.
   */
  private dedupedRestore(): Promise<void> {
    if (!this.restorePromise) {
      this.restorePromise = this.withRestoreLock(() => this.performRestore())
        .then(() => {
          this.restoreFailures = 0;
        })
        .catch(error => {
          this.restoreFailures++;
          throw error;
        })
        .finally(() => {
          this.restorePromise = null;
        });
    }
    return this.restorePromise;
  }

  /**
   * Serializes restores across tabs. Each restore rotates the session cookie,
   * and the server revokes a session when a superseded cookie is presented.
   * Runs unlocked where the Web Locks API is unavailable.
   */
  private async withRestoreLock(restore: () => Promise<void>): Promise<void> {
    const locks = globalThis.navigator?.locks;
    if (!locks) {
      return restore();
    }
    await locks.request(`ignoti:restore:${this.backendUrl}`, restore);
  }

  private async handleUnauthorized(method: string, path: string): Promise<Record<string, string>> {
    await this.restoreOnce();
    const { sessionId } = this.requireActiveSession();
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const signature = await this.signWithSessionKey({
      htm: method.toUpperCase(),
      htu: this.backendHtu(path),
      iat,
      jti,
      sessionId,
    });

    return {
      [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${sessionId}`,
      [HTTP_HEADERS.SESSION_NONCE]: jti,
      [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
      [HTTP_HEADERS.SESSION_SIGNATURE]: signature,
    };
  }

  onSessionChange(callback: (session: SessionInfo | null) => void): void {
    this.sessionChangeCallback = callback;
  }

  private notifySessionChange(): void {
    this.sessionChangeCallback?.(this.getSession());
  }

  init(): void {
    if (this.initialized) {
      return;
    }
    this.initialized = true;
  }

  async restoreSession(): Promise<void> {
    this.ensureInitialized();
    await this.dedupedRestore();
  }

  /**
   * Resumes the session bound to the stored keypair. Falls back to the
   * in-memory keypair when storage holds none. Never generates a new key:
   * the server only accepts the key the session was created with.
   */
  private async performRestore(): Promise<void> {
    const stored = await this.sessionKeys.load();
    const keyPair =
      stored ??
      (this.session && {
        privateKey: this.session.sessionPrivateKey,
        publicKey: this.session.sessionPublicKey,
      });
    if (!keyPair) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    try {
      const nonce = crypto.randomUUID();
      const sessionBinding = await signSessionBindingJWS(
        { sessionChallenge: nonce },
        keyPair.privateKey,
        keyPair.publicKey
      );
      const response = await this.apiClient.auth.restoreSession(sessionBinding);
      this.session = {
        sessionId: response.sessionId,
        userId: response.userId,
        deviceId: response.deviceId,
        expiresAt: response.expiresAt,
        sessionPrivateKey: keyPair.privateKey,
        sessionPublicKey: keyPair.publicKey,
      };
      this.notifySessionChange();
    } catch (error) {
      if (error instanceof IgnotiError && error.httpStatus === 401) {
        if (stored) {
          await this.sessionKeys.clear();
        }
        throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
      }
      throw error;
    }
  }

  /** Ends the local session after the server has revoked it. */
  private async endSession(): Promise<void> {
    this.session = null;
    await this.sessionKeys.clear();
    this.notifySessionChange();
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new IgnotiError(ERROR_MESSAGES.NOT_INITIALIZED, ErrorCodes.NOT_INITIALIZED);
    }
  }

  /**
   * Creates a new identity end-to-end:
   *   1. Generate mnemonic and root keys.
   *   2. POST /register with rootPublicKey -> server returns userId and WebAuthn options.
   *   3. Browser produces a passkey credential.
   *   4. SDK signs a device-binding JWS with the root key.
   *   5. POST /register/device with the registration response and root signature.
   *
   * Caller must persist the returned mnemonic offline (it is the only recovery path).
   */
  async createIdentity(): Promise<CreateIdentityResult> {
    this.ensureInitialized();
    if (!isWebAuthnSupported()) {
      throw new IgnotiError(ERROR_MESSAGES.WEB_AUTHN_NOT_SUPPORTED, ErrorCodes.INVALID_INPUT);
    }

    const mnemonic = generateMnemonic();
    const rootKeySet = await deriveRootKeysFromMnemonic(mnemonic.join(' '));
    const rootPublicKey = toBase64(rootKeySet.signing.publicKey);

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
        attestationHash: await sha256Base64Url(passkeyResponse.response.attestationObject),
      },
      rootKeySet.signing.privateKey
    );

    const deviceResponse = await this.apiClient.auth.registerDevice({
      userId,
      registrationResponse: passkeyResponse,
      rootSignature,
      deviceName: this.defaultDeviceName ?? this.guessDeviceName(),
    });

    return { mnemonic, userId, deviceId: deviceResponse.deviceId };
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
  async login(): Promise<SessionInfo> {
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
      sessionPublicKey: sessionKeyPair.publicKey,
    };
    await this.sessionKeys.save(sessionKeyPair);
    this.restoreFailures = 0;
    this.notifySessionChange();

    return {
      sessionId: sessionResponse.sessionId,
      userId: sessionResponse.userId,
      deviceId: loginResponse.deviceId,
      expiresAt: sessionResponse.expiresAt,
    };
  }

  /**
   * Recovers an account using the mnemonic. Server looks up the user by the
   * derived root public key and issues a registration challenge for a new
   * device. The returned userId matches the original; the deviceId is new.
   */
  async recoverIdentity(mnemonic: string): Promise<RecoverIdentityResult> {
    this.ensureInitialized();
    if (!isWebAuthnSupported()) {
      throw new IgnotiError(ERROR_MESSAGES.WEB_AUTHN_NOT_SUPPORTED, ErrorCodes.INVALID_INPUT);
    }

    const rootKeySet = await deriveRootKeysFromMnemonic(mnemonic);
    const rootPublicKey = toBase64(rootKeySet.signing.publicKey);

    // Resolve the account before prompting for a passkey. A 404 means the
    // mnemonic matches no account; surfacing it here avoids minting an orphan
    // credential in the authenticator for a wrong recovery phrase.
    let recoverResponse: Awaited<ReturnType<typeof this.apiClient.auth.recoverAccount>>;
    try {
      recoverResponse = await this.apiClient.auth.recoverAccount({ rootPublicKey });
    } catch (error) {
      if (error instanceof IgnotiError && error.httpStatus === 404) {
        throw new IgnotiError(ERROR_MESSAGES.NO_ACCOUNT_FOR_MNEMONIC, ErrorCodes.INVALID_INPUT);
      }
      throw error;
    }
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
        attestationHash: await sha256Base64Url(passkeyResponse.response.attestationObject),
      },
      rootKeySet.signing.privateKey
    );

    const deviceResponse = await this.apiClient.auth.registerDevice({
      userId,
      registrationResponse: passkeyResponse,
      rootSignature,
      deviceName: this.defaultDeviceName ?? this.guessDeviceName(),
    });

    return { userId, deviceId: deviceResponse.deviceId };
  }

  async recoverAndLogin(mnemonic: string): Promise<SessionInfo> {
    await this.recoverIdentity(mnemonic);
    return this.login();
  }

  /**
   * Reads the active session, throwing NO_KEYS if it is absent. Used after an
   * await, where a concurrent logout/revoke may have cleared it in the gap.
   */
  private requireActiveSession(): ActiveSession {
    if (!this.session) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    return this.session;
  }

  private async signWithSessionKey(payload: Record<string, unknown>): Promise<string> {
    this.ensureInitialized();
    return ApiClient.signRequest(payload, this.requireActiveSession().sessionPrivateKey);
  }

  /**
   * Returns headers that authenticate a specific request to the integrator's own backend.
   * The backend validates them by forwarding to the Ignoti server's
   * POST /api/sessions/verify endpoint.
   *
   * Every call generates a fresh nonce and signature, do not cache or reuse the result.
   * `url` is the request URL including any query string; a relative URL resolves
   * against the page URL. The headers are valid only for that method and URL.
   */
  async getSessionHeaders(method: string, url: string): Promise<Record<string, string>> {
    this.ensureInitialized();
    if (!this.session) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const htu = this.resolveHtu(url);
    if (this.isSessionExpired()) {
      await this.restoreOnce();
    }
    const { sessionId } = this.requireActiveSession();
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const htm = method.toUpperCase();
    const signature = await this.signWithSessionKey({ htm, htu, iat, jti, sessionId });
    return {
      [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${sessionId}`,
      [HTTP_HEADERS.SESSION_NONCE]: jti,
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
    const jti = crypto.randomUUID();
    const htu = this.backendHtu(`${API_ENDPOINTS.SESSIONS.REVOKE}/${sessionId}`);
    const signature = await ApiClient.signRequest(
      { htm: 'DELETE', htu, iat, jti, sessionId },
      sessionPrivateKey
    );
    // Clear local state only after the server confirms revocation. If the call
    // throws, the session stays intact (the user is still logged in) and the
    // error propagates so the caller can surface it and retry.
    await this.apiClient.sessions.revokeSession(sessionId, sessionId, iat, signature, jti);
    await this.endSession();
  }

  async getDevices(): Promise<DeviceInfo[]> {
    this.ensureInitialized();
    if (!this.session) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const signature = await this.signWithSessionKey({
      htm: 'GET',
      htu: this.backendHtu(API_ENDPOINTS.DEVICES.LIST),
      iat,
      jti,
      sessionId,
    });
    const response = await this.apiClient.devices.getDevices(sessionId, iat, signature, jti);
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
    const rootSignature = await signDeviceBindingJWS(
      { purpose: 'revoke-device', userId, credentialId, challenge: deviceId },
      rootKeySet.signing.privateKey
    );
    await this.apiClient.devices.revokeDevice(deviceId, rootSignature);

    // Revoking a device also revokes its sessions server-side; if it backed the
    // current session, that session is now dead, so clear local state.
    if (this.session?.deviceId === deviceId) {
      await this.endSession();
    }
  }

  async getSessions(): Promise<SessionListItem[]> {
    this.ensureInitialized();
    if (!this.session) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const signature = await this.signWithSessionKey({
      htm: 'GET',
      htu: this.backendHtu(API_ENDPOINTS.SESSIONS.LIST),
      iat,
      jti,
      sessionId,
    });
    const response = await this.apiClient.sessions.getSessions(sessionId, iat, signature, jti);
    return response.sessions.map(
      (s): SessionListItem => ({
        id: s.id,
        deviceId: s.deviceId,
        createdAt: s.createdAt,
        lastUsedAt: s.lastUsedAt,
        expiresAt: new Date(s.expiresAt).getTime(),
        isCurrent: s.isCurrent,
      })
    );
  }

  async revokeSession(targetSessionId: string): Promise<void> {
    this.ensureInitialized();
    if (!this.session) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const htu = this.backendHtu(`${API_ENDPOINTS.SESSIONS.REVOKE}/${targetSessionId}`);
    const signature = await this.signWithSessionKey({ htm: 'DELETE', htu, iat, jti, sessionId });
    await this.apiClient.sessions.revokeSession(targetSessionId, sessionId, iat, signature, jti);
    if (targetSessionId === sessionId) {
      await this.endSession();
    }
  }

  /**
   * Revokes every active session for the current user across all devices,
   * including this one. Devices remain registered so the user can log back
   * in with any of their passkeys. The current session is cleared and
   * `onSessionChange` fires with null.
   */
  async revokeAllSessions(): Promise<void> {
    this.ensureInitialized();
    if (!this.session) {
      throw new IgnotiError(ERROR_MESSAGES.NO_ACTIVE_SESSION, ErrorCodes.NO_KEYS);
    }
    const { sessionId } = this.session;
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const signature = await this.signWithSessionKey({
      htm: 'DELETE',
      htu: this.backendHtu(API_ENDPOINTS.SESSIONS.LIST),
      iat,
      jti,
      sessionId,
    });
    await this.apiClient.sessions.revokeAllSessions(sessionId, iat, signature, jti);
    await this.endSession();
  }

  /**
   * Returns information about the active session, or null if logged out or the
   * session has passed its expiry. The session private key is intentionally not
   * exposed.
   */
  getSession(): SessionInfo | null {
    this.clearIfExpired();
    if (!this.session) return null;
    return {
      sessionId: this.session.sessionId,
      userId: this.session.userId,
      deviceId: this.session.deviceId,
      expiresAt: this.session.expiresAt,
    };
  }

  isSessionExpired(): boolean {
    if (!this.session) {
      return true;
    }
    return Date.now() > this.session.expiresAt;
  }

  /**
   * Drops the in-memory session once it is past expiry and notifies subscribers.
   * Clears before notifying so the re-entrant getSession() inside
   * notifySessionChange() observes the null state and does not recurse.
   */
  private clearIfExpired(): void {
    if (this.session && Date.now() > this.session.expiresAt) {
      this.session = null;
      this.notifySessionChange();
    }
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

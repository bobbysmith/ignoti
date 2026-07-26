import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ErrorCodes, GhostIDError } from '@/core/errors.ts';
import { GhostID } from '@/ghostid.ts';

const {
  mockGenerateMnemonic,
  mockDeriveRootKeys,
  mockGenerateSessionKeypair,
  mockToBase64,
  mockBufferToBase64Url,
  mockBase64UrlToBuffer,
} = vi.hoisted(() => ({
  mockGenerateMnemonic: vi.fn(),
  mockDeriveRootKeys: vi.fn(),
  mockGenerateSessionKeypair: vi.fn(),
  mockToBase64: vi.fn(),
  mockBufferToBase64Url: vi.fn(),
  mockBase64UrlToBuffer: vi.fn(),
}));

const { mockIsWebAuthnSupported, mockCreatePasskey, mockGetPasskeyAssertion } = vi.hoisted(() => ({
  mockIsWebAuthnSupported: vi.fn(),
  mockCreatePasskey: vi.fn(),
  mockGetPasskeyAssertion: vi.fn(),
}));

const { mockSignDeviceBindingJWS } = vi.hoisted(() => ({ mockSignDeviceBindingJWS: vi.fn() }));

const onUnauthorizedRef = vi.hoisted(() => ({
  current: undefined as
    | ((method: string, path: string) => Promise<Record<string, string>>)
    | undefined,
}));
vi.mock('@/api/root-jws.ts', () => ({ signDeviceBindingJWS: mockSignDeviceBindingJWS }));

const { mockSignSessionBindingJWS } = vi.hoisted(() => ({
  mockSignSessionBindingJWS: vi.fn(),
}));
vi.mock('@/api/session-jws.ts', () => ({ signSessionBindingJWS: mockSignSessionBindingJWS }));

const {
  mockApiClientSignRequest,
  mockRegisterUser,
  mockRegisterDevice,
  mockRequestChallenge,
  mockLogin,
  mockCreateSession,
  mockRestoreSession,
  mockRecoverAccount,
  mockGetDevices,
  mockRevokeDevice,
  mockGetSessions,
  mockRevokeSession,
  mockRevokeAllSessions,
} = vi.hoisted(() => ({
  mockApiClientSignRequest: vi.fn(),
  mockRegisterUser: vi.fn(),
  mockRegisterDevice: vi.fn(),
  mockRequestChallenge: vi.fn(),
  mockLogin: vi.fn(),
  mockCreateSession: vi.fn(),
  mockRestoreSession: vi.fn(),
  mockRecoverAccount: vi.fn(),
  mockGetDevices: vi.fn(),
  mockRevokeDevice: vi.fn(),
  mockGetSessions: vi.fn(),
  mockRevokeSession: vi.fn(),
  mockRevokeAllSessions: vi.fn(),
}));

vi.mock('@/core/crypto.ts', () => ({
  generateMnemonic: mockGenerateMnemonic,
  deriveRootKeysFromMnemonic: mockDeriveRootKeys,
  generateSessionSigningKeypair: mockGenerateSessionKeypair,
  toBase64: mockToBase64,
  bufferToBase64Url: mockBufferToBase64Url,
  base64UrlToBuffer: mockBase64UrlToBuffer,
}));

vi.mock('@/auth/passkey.ts', () => ({
  isWebAuthnSupported: mockIsWebAuthnSupported,
  createPasskey: mockCreatePasskey,
  getPasskeyAssertion: mockGetPasskeyAssertion,
}));

vi.mock('@/api/client.ts', () => {
  class ApiClient {
    auth = {
      registerUser: mockRegisterUser,
      registerDevice: mockRegisterDevice,
      requestChallenge: mockRequestChallenge,
      login: mockLogin,
      createSession: mockCreateSession,
      restoreSession: mockRestoreSession,
      recoverAccount: mockRecoverAccount,
    };
    devices = {
      getDevices: mockGetDevices,
      revokeDevice: mockRevokeDevice,
    };
    sessions = {
      getSessions: mockGetSessions,
      revokeSession: mockRevokeSession,
      revokeAllSessions: mockRevokeAllSessions,
    };
    static signRequest = mockApiClientSignRequest;
    static verifyRequest = vi.fn();
  }
  return {
    ApiClient,
    createApiClient: (opts: {
      onUnauthorized?: (method: string, path: string) => Promise<Record<string, string>>;
    }) => {
      onUnauthorizedRef.current = opts.onUnauthorized;
      return new ApiClient();
    },
  };
});

const ROOT_PRIVATE_KEY = {} as unknown as CryptoKey;
const ROOT_PUBLIC_KEY = new Uint8Array(32).fill(2);
const SESSION_PRIVATE_KEY = new Uint8Array(32).fill(3);
const SESSION_PUBLIC_KEY = new Uint8Array(32).fill(4);

function makeRootKeySet() {
  return { signing: { privateKey: ROOT_PRIVATE_KEY, publicKey: ROOT_PUBLIC_KEY } };
}

function makePasskeyResponse() {
  return {
    id: 'cred-id',
    rawId: 'rawId-b64',
    type: 'public-key' as const,
    clientExtensionResults: {},
    response: { clientDataJSON: 'cdj', attestationObject: 'ao' },
  };
}

function makeOptions(overrides: Record<string, unknown> = {}) {
  return {
    challenge: 'Y2hhbGxlbmdl',
    user: { id: 'dXNlcg', name: 'alice', displayName: 'Alice' },
    rp: { name: 'Test' },
    pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }],
    ...overrides,
  };
}

function sdk() {
  return new GhostID({ backendUrl: 'http://localhost' });
}

function initializedSdk() {
  const g = sdk();
  g.init();
  return g;
}

function stubCreateIdentityMocks(registerUserOptions = makeOptions()) {
  mockIsWebAuthnSupported.mockReturnValue(true);
  mockGenerateMnemonic.mockReturnValue('word '.repeat(12).trim().split(' '));
  mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
  mockRegisterUser.mockResolvedValue({ userId: 'user-1', options: registerUserOptions });
  mockCreatePasskey.mockResolvedValue(makePasskeyResponse());
  mockRegisterDevice.mockResolvedValue({ deviceId: 'device-1', credentialId: 'cred-id' });
}

function stubLoginMocks(
  opts: { expiresAt?: number; challengeOptions?: ReturnType<typeof makeOptions> } = {}
) {
  const expiresAt = opts.expiresAt ?? Date.now() + 3_600_000;
  mockRequestChallenge.mockResolvedValue({ options: opts.challengeOptions ?? makeOptions() });
  mockGetPasskeyAssertion.mockResolvedValue({ id: 'cred', type: 'public-key' });
  mockLogin.mockResolvedValue({ sessionChallenge: 'ch', deviceId: 'device-1' });
  mockGenerateSessionKeypair.mockResolvedValue({
    privateKey: SESSION_PRIVATE_KEY,
    publicKey: SESSION_PUBLIC_KEY,
  });
  mockCreateSession.mockResolvedValue({ sessionId: 'sess-1', expiresAt, userId: 'user-1' });
  return { sessionId: 'sess-1', expiresAt, userId: 'user-1', deviceId: 'device-1' };
}

async function withSession(opts?: Parameters<typeof stubLoginMocks>[0]) {
  const info = stubLoginMocks(opts);
  const g = initializedSdk();
  await g.login();
  return { g, ...info };
}

describe('GhostID', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    onUnauthorizedRef.current = undefined;
    mockBase64UrlToBuffer.mockReturnValue(new Uint8Array(32).buffer);
    mockBufferToBase64Url.mockReturnValue('challenge-b64url');
    mockToBase64.mockReturnValue('root-pub-b64');
    mockSignDeviceBindingJWS.mockResolvedValue('root-sig');
    mockSignSessionBindingJWS.mockResolvedValue('session-binding');
    mockApiClientSignRequest.mockResolvedValue('sig-abc');
  });

  afterEach(() => vi.useRealTimers());

  describe('ensureInitialized', () => {
    it('throws NOT_INITIALIZED before init()', async () => {
      const g = sdk();
      await expect(g.createIdentity()).rejects.toThrow(GhostIDError);
      await expect(g.createIdentity()).rejects.toThrow('init()');
    });

    it('does not throw after init()', () => {
      const g = sdk();
      g.init();
      expect(() => g.getSession()).not.toThrow();
    });
  });

  describe('createIdentity', () => {
    it('throws when WebAuthn is not supported', async () => {
      mockIsWebAuthnSupported.mockReturnValue(false);
      const g = initializedSdk();
      await expect(g.createIdentity()).rejects.toThrow(GhostIDError);
    });

    it('registers user, creates passkey, registers device and returns mnemonic', async () => {
      stubCreateIdentityMocks();

      const g = initializedSdk();
      const result = await g.createIdentity();

      expect(Array.isArray(result.mnemonic)).toBe(true);
      expect(result.mnemonic.length).toBe(12);
      expect(result.userId).toBe('user-1');
      expect(result.deviceId).toBe('device-1');
      expect(mockRegisterUser).toHaveBeenCalledWith({ rootPublicKey: 'root-pub-b64' });
      expect(mockCreatePasskey).toHaveBeenCalled();
      expect(mockRegisterDevice).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', rootSignature: 'root-sig' })
      );
    });
  });

  describe('login', () => {
    it('returns full SessionInfo on success', async () => {
      const info = stubLoginMocks();
      const g = initializedSdk();
      const result = await g.login();

      expect(result).toEqual({
        sessionId: info.sessionId,
        userId: info.userId,
        deviceId: info.deviceId,
        expiresAt: info.expiresAt,
      });
      expect(g.getSession()).toMatchObject({ sessionId: info.sessionId, deviceId: 'device-1' });
    });

    it('rethrows when signSessionBindingJWS throws', async () => {
      stubLoginMocks();
      mockSignSessionBindingJWS.mockRejectedValue(new Error('jws fail'));
      await expect(initializedSdk().login()).rejects.toThrow('jws fail');
    });
  });

  describe('logout', () => {
    it('revokes session server-side, wipes key, and clears session', async () => {
      const { g, sessionId } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      await g.logout();

      expect(mockRevokeSession).toHaveBeenCalledWith(
        sessionId,
        sessionId,
        expect.any(Number),
        'sig-abc',
        expect.any(String)
      );
      expect(g.getSession()).toBeNull();
    });

    it('clears local session before network call so state is clean even if server revocation fails', async () => {
      const { g } = await withSession();
      mockRevokeSession.mockRejectedValue(new Error('network'));
      await expect(g.logout()).rejects.toThrow('network');
      expect(g.getSession()).toBeNull();
    });

    it('is a no-op when no session is active', async () => {
      const g = initializedSdk();
      await expect(g.logout()).resolves.toBeUndefined();
      expect(mockRevokeSession).not.toHaveBeenCalled();
    });
  });

  describe('getSession', () => {
    it('returns null when not logged in', () => {
      expect(initializedSdk().getSession()).toBeNull();
    });

    it('does not expose sessionPrivateKey', async () => {
      const { g } = await withSession();
      const info = g.getSession();
      expect(info).not.toHaveProperty('sessionPrivateKey');
      expect(info).toMatchObject({ sessionId: 'sess-1', userId: 'user-1', deviceId: 'device-1' });
    });

    it('returns null once the session has passed its expiry', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      expect(g.getSession()).toBeNull();
    });

    it('fires onSessionChange(null) the first time an expired session is observed', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      const cb = vi.fn();
      g.onSessionChange(cb);

      expect(g.getSession()).toBeNull();
      expect(cb).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledWith(null);

      // Session is already cleared: a second read neither returns it nor re-fires.
      expect(g.getSession()).toBeNull();
      expect(cb).toHaveBeenCalledTimes(1);
    });
  });

  describe('isSessionExpired', () => {
    it('returns true when no session', () => {
      expect(initializedSdk().isSessionExpired()).toBe(true);
    });

    it('returns false when session is active', async () => {
      const { g } = await withSession();
      expect(g.isSessionExpired()).toBe(false);
    });

    it('returns true when session is past expiresAt', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      expect(g.isSessionExpired()).toBe(true);
    });
  });

  describe('getSessionHeaders', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.getSessionHeaders('GET', '/api/data')).rejects.toThrow(GhostIDError);
    });

    it('propagates restore error when session is expired and restore fails', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      mockGenerateSessionKeypair.mockRejectedValue(new Error('restore failed'));
      await expect(g.getSessionHeaders('GET', '/api/data')).rejects.toThrow('restore failed');
    });

    it('stops attempting restore after the failure cap, same as the 401 interceptor', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      mockGenerateSessionKeypair.mockClear();
      mockGenerateSessionKeypair.mockRejectedValue(new Error('restore failed'));

      for (let i = 0; i < 3; i++) {
        await expect(g.getSessionHeaders('GET', '/api/data')).rejects.toThrow('restore failed');
      }

      const err = (await g.getSessionHeaders('GET', '/api/data').catch(e => e)) as GhostIDError;
      expect(err.code).toBe('NO_KEYS');
      expect(mockGenerateSessionKeypair).toHaveBeenCalledTimes(3);
    });

    it('returns Authorization, Nonce, Timestamp, and Signature headers', async () => {
      const { g, sessionId } = await withSession();
      const headers = await g.getSessionHeaders('GET', '/api/data');
      expect(headers.Authorization).toBe(`GhostID-Session ${sessionId}`);
      expect(headers['X-GhostID-Nonce']).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
      expect(headers['X-GhostID-Timestamp']).toMatch(/^\d+$/);
      expect(headers['X-GhostID-Signature']).toBe('sig-abc');
    });

    it('proactively restores when expired and returns headers from the new session', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      mockRestoreSession.mockResolvedValue({
        sessionId: 'sess-restored',
        userId: 'user-1',
        deviceId: 'device-1',
        expiresAt: Date.now() + 3_600_000,
      });

      const headers = await g.getSessionHeaders('GET', '/api/data');

      expect(mockRestoreSession).toHaveBeenCalledTimes(1);
      expect(headers.Authorization).toBe('GhostID-Session sess-restored');
      expect(headers['X-GhostID-Signature']).toBe('sig-abc');
    });
  });

  describe('restoreSession single-flight', () => {
    it('deduplicates concurrent restoreSession() calls into one attempt', async () => {
      const g = initializedSdk();
      mockGenerateSessionKeypair.mockClear();
      mockRestoreSession.mockClear();
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      mockRestoreSession.mockResolvedValue({
        sessionId: 'sess-restored',
        userId: 'user-1',
        deviceId: 'device-1',
        expiresAt: Date.now() + 3_600_000,
      });
      const cb = vi.fn();
      g.onSessionChange(cb);

      await Promise.all([g.restoreSession(), g.restoreSession(), g.restoreSession()]);

      // One shared attempt: one keypair, one network call, one notification —
      // so concurrent callers cannot bind mismatched keys.
      expect(mockGenerateSessionKeypair).toHaveBeenCalledTimes(1);
      expect(mockRestoreSession).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledTimes(1);
    });
  });

  describe('getDevices', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.getDevices()).rejects.toThrow(GhostIDError);
    });

    it('returns device list on success', async () => {
      const { g } = await withSession();
      mockGetDevices.mockResolvedValue({
        devices: [{ id: 'device-1', credentialId: 'cred-id', name: 'My Device', createdAt: 0 }],
      });
      const devices = await g.getDevices();
      expect(devices).toHaveLength(1);
      expect(devices[0].id).toBe('device-1');
    });
  });

  describe('revokeDevice', () => {
    const MNEMONIC = 'word '.repeat(12).trim();

    it('works without an active session', async () => {
      const g = initializedSdk();
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRevokeDevice.mockResolvedValue({ ok: true });

      await expect(
        g.revokeDevice('device-1', MNEMONIC, 'user-1', 'cred-id')
      ).resolves.toBeUndefined();
    });

    it('calls revokeDevice API with correct deviceId and root signature', async () => {
      const g = initializedSdk();
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRevokeDevice.mockResolvedValue({ ok: true });

      await g.revokeDevice('device-1', MNEMONIC, 'user-1', 'cred-id');

      expect(mockRevokeDevice).toHaveBeenCalledWith('device-1', 'root-sig');
    });

    it('clears local state and fires onSessionChange when revoking the current device', async () => {
      const { g } = await withSession(); // session is bound to device-1
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRevokeDevice.mockResolvedValue({ ok: true });
      const cb = vi.fn();
      g.onSessionChange(cb);

      await g.revokeDevice('device-1', MNEMONIC, 'user-1', 'cred-id');

      expect(cb).toHaveBeenCalledWith(null);
      expect(g.getSession()).toBeNull();
    });

    it('leaves the current session intact when revoking a different device', async () => {
      const { g, sessionId } = await withSession(); // session is bound to device-1
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRevokeDevice.mockResolvedValue({ ok: true });
      const cb = vi.fn();
      g.onSessionChange(cb);

      await g.revokeDevice('device-2', MNEMONIC, 'user-1', 'cred-id');

      expect(cb).not.toHaveBeenCalled();
      expect(g.getSession()?.sessionId).toBe(sessionId);
    });
  });

  describe('getSessions', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.getSessions()).rejects.toThrow(GhostIDError);
    });

    it('returns session list on success', async () => {
      const { g } = await withSession();
      mockGetSessions.mockResolvedValue({
        sessions: [
          {
            id: 'sess-1',
            deviceId: 'device-1',
            createdAt: '2024-01-01T00:00:00.000Z',
            lastUsedAt: null,
            expiresAt: '2024-01-08T00:00:00.000Z',
            isCurrent: true,
          },
        ],
      });
      const sessions = await g.getSessions();
      expect(sessions).toHaveLength(1);
      expect(sessions[0].id).toBe('sess-1');
      expect(sessions[0].expiresAt).toBe(new Date('2024-01-08T00:00:00.000Z').getTime());
    });

    it('calls getSessions with correct session auth args', async () => {
      const { g, sessionId } = await withSession();
      mockGetSessions.mockResolvedValue({ sessions: [] });
      await g.getSessions();
      expect(mockGetSessions).toHaveBeenCalledWith(
        sessionId,
        expect.any(Number),
        'sig-abc',
        expect.any(String)
      );
    });
  });

  describe('revokeSession', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.revokeSession('other-sess')).rejects.toThrow(GhostIDError);
    });

    it('revokes another session without clearing local session', async () => {
      const { g, sessionId } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      await g.revokeSession('other-sess');
      expect(mockRevokeSession).toHaveBeenCalledWith(
        'other-sess',
        sessionId,
        expect.any(Number),
        'sig-abc',
        expect.any(String)
      );
      expect(g.getSession()).not.toBeNull();
    });

    it('wipes session key and clears session when revoking own session', async () => {
      const { g, sessionId } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      await g.revokeSession(sessionId);
      expect(g.getSession()).toBeNull();
    });
  });

  describe('revokeAllSessions', () => {
    it('throws NO_KEYS when no active session', async () => {
      const g = initializedSdk();
      await expect(g.revokeAllSessions()).rejects.toThrow(GhostIDError);
    });

    it('calls the API with signed session headers', async () => {
      const { g, sessionId } = await withSession();
      mockRevokeAllSessions.mockResolvedValue({ revoked: 3 });
      await g.revokeAllSessions();
      expect(mockRevokeAllSessions).toHaveBeenCalledWith(
        sessionId,
        expect.any(Number),
        'sig-abc',
        expect.any(String)
      );
    });

    it('clears local session and fires onSessionChange with null', async () => {
      const { g } = await withSession();
      mockRevokeAllSessions.mockResolvedValue({ revoked: 2 });
      const cb = vi.fn();
      g.onSessionChange(cb);
      await g.revokeAllSessions();
      expect(g.getSession()).toBeNull();
      expect(cb).toHaveBeenCalledWith(null);
    });
  });

  describe('recoverIdentity', () => {
    it('throws when WebAuthn is not supported', async () => {
      mockIsWebAuthnSupported.mockReturnValue(false);
      const g = initializedSdk();
      await expect(g.recoverIdentity('mnemonic')).rejects.toThrow(GhostIDError);
    });

    it('recovers account and returns userId + new deviceId', async () => {
      mockIsWebAuthnSupported.mockReturnValue(true);
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRecoverAccount.mockResolvedValue({ userId: 'user-1', options: makeOptions() });
      mockCreatePasskey.mockResolvedValue(makePasskeyResponse());
      mockRegisterDevice.mockResolvedValue({ deviceId: 'device-2', credentialId: 'cred-id' });

      const g = initializedSdk();
      const result = await g.recoverIdentity('word '.repeat(12).trim());

      expect(result.userId).toBe('user-1');
      expect(result.deviceId).toBe('device-2');
    });

    it('maps a 404 to INVALID_INPUT and never prompts for a passkey', async () => {
      mockIsWebAuthnSupported.mockReturnValue(true);
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRecoverAccount.mockRejectedValue(
        new GhostIDError('user_not_found', ErrorCodes.API_ERROR, undefined, 404)
      );

      const g = initializedSdk();
      const err = (await g
        .recoverIdentity('word '.repeat(12).trim())
        .catch(e => e)) as GhostIDError;

      expect(err).toBeInstanceOf(GhostIDError);
      expect(err.code).toBe(ErrorCodes.INVALID_INPUT);
      expect(mockCreatePasskey).not.toHaveBeenCalled();
    });
  });

  describe('onSessionChange', () => {
    it('fires with session info after login', async () => {
      const cb = vi.fn();
      const info = stubLoginMocks();
      const g = initializedSdk();
      g.onSessionChange(cb);
      await g.login();
      expect(cb).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledWith(expect.objectContaining({ sessionId: info.sessionId }));
    });

    it('fires with null after logout', async () => {
      const { g } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      const cb = vi.fn();
      g.onSessionChange(cb);
      await g.logout();
      expect(cb).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledWith(null);
    });

    it('fires with session info after restoreSession', async () => {
      const cb = vi.fn();
      const g = initializedSdk();
      g.onSessionChange(cb);
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      mockRestoreSession.mockResolvedValue({
        sessionId: 'sess-restored',
        userId: 'user-1',
        deviceId: 'device-1',
        expiresAt: Date.now() + 3_600_000,
      });
      await g.restoreSession();
      expect(cb).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledWith(expect.objectContaining({ sessionId: 'sess-restored' }));
    });

    it('fires with null when revoking the current session', async () => {
      const { g, sessionId } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      const cb = vi.fn();
      g.onSessionChange(cb);
      await g.revokeSession(sessionId);
      expect(cb).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledWith(null);
    });

    it('does not fire when revoking a different session', async () => {
      const { g } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      const cb = vi.fn();
      g.onSessionChange(cb);
      await g.revokeSession('other-session');
      expect(cb).not.toHaveBeenCalled();
    });

    it('does not throw when no callback is registered', async () => {
      const info = stubLoginMocks();
      const g = initializedSdk();
      await expect(g.login()).resolves.toMatchObject({ sessionId: info.sessionId });
    });
  });

  describe('recoverAndLogin', () => {
    it('recovers identity then logs in and returns SessionInfo', async () => {
      mockIsWebAuthnSupported.mockReturnValue(true);
      mockDeriveRootKeys.mockResolvedValue(makeRootKeySet());
      mockRecoverAccount.mockResolvedValue({ userId: 'user-1', options: makeOptions() });
      mockCreatePasskey.mockResolvedValue(makePasskeyResponse());
      mockRegisterDevice.mockResolvedValue({ deviceId: 'device-2', credentialId: 'cred-id' });
      const info = stubLoginMocks();

      const g = initializedSdk();
      const result = await g.recoverAndLogin('word '.repeat(12).trim());

      expect(result).toMatchObject({
        sessionId: info.sessionId,
        userId: info.userId,
        deviceId: info.deviceId,
      });
      expect(g.getSession()).not.toBeNull();
    });
  });

  describe('onUnauthorized interceptor callback', () => {
    function capturedOnUnauthorized() {
      const cb = onUnauthorizedRef.current;
      if (!cb) {
        throw new Error('onUnauthorized not captured — was GhostID constructed?');
      }
      return cb;
    }

    function stubRestoreSuccess(sessionId = 'sess-restored') {
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      mockRestoreSession.mockResolvedValue({
        sessionId,
        userId: 'user-1',
        deviceId: 'device-1',
        expiresAt: Date.now() + 3_600_000,
      });
    }

    it('restores session, re-signs, and returns fresh session headers', async () => {
      await withSession();
      stubRestoreSuccess();
      const onUnauthorized = capturedOnUnauthorized();

      const headers = await onUnauthorized('GET', '/api/devices');

      expect(mockRestoreSession).toHaveBeenCalledTimes(1);
      expect(headers.Authorization).toBe('GhostID-Session sess-restored');
      expect(headers['X-GhostID-Signature']).toBe('sig-abc');
      expect(headers['X-GhostID-Nonce']).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
      expect(headers['X-GhostID-Timestamp']).toMatch(/^\d+$/);
    });

    it('uppercases the http method in the signed payload', async () => {
      await withSession();
      stubRestoreSuccess();
      const onUnauthorized = capturedOnUnauthorized();

      await onUnauthorized('delete', '/api/sessions/sess-1');

      expect(mockApiClientSignRequest).toHaveBeenLastCalledWith(
        expect.objectContaining({ htm: 'DELETE', htu: '/api/sessions/sess-1' }),
        expect.anything()
      );
    });

    it('deduplicates concurrent restore calls', async () => {
      await withSession();
      stubRestoreSuccess();
      const onUnauthorized = capturedOnUnauthorized();

      await Promise.all([
        onUnauthorized('GET', '/api/devices'),
        onUnauthorized('GET', '/api/sessions'),
      ]);

      expect(mockRestoreSession).toHaveBeenCalledTimes(1);
    });

    it('propagates restore failure to the caller', async () => {
      await withSession();
      mockGenerateSessionKeypair.mockRejectedValue(new Error('restore failed'));
      const onUnauthorized = capturedOnUnauthorized();

      await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');
    });

    it('updates the active session after a successful restore', async () => {
      const { g } = await withSession();
      stubRestoreSuccess('sess-brand-new');
      const onUnauthorized = capturedOnUnauthorized();

      await onUnauthorized('GET', '/api/devices');

      expect(g.getSession()?.sessionId).toBe('sess-brand-new');
    });

    it('stops attempting restore after three consecutive failures', async () => {
      await withSession();
      mockGenerateSessionKeypair.mockClear();
      mockGenerateSessionKeypair.mockRejectedValue(new Error('restore failed'));
      const onUnauthorized = capturedOnUnauthorized();

      for (let i = 0; i < 3; i++) {
        await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');
      }

      const err = (await onUnauthorized('GET', '/api/devices').catch(e => e)) as GhostIDError;
      expect(err.code).toBe('NO_KEYS');
      expect(mockGenerateSessionKeypair).toHaveBeenCalledTimes(3);
    });

    it('counts one failure per restore attempt, not per concurrent caller', async () => {
      await withSession();
      mockGenerateSessionKeypair.mockClear();
      mockGenerateSessionKeypair.mockRejectedValue(new Error('restore failed'));
      const onUnauthorized = capturedOnUnauthorized();

      // Three concurrent 401s share one failed restore attempt
      const results = await Promise.allSettled([
        onUnauthorized('GET', '/api/devices'),
        onUnauthorized('GET', '/api/sessions'),
        onUnauthorized('DELETE', '/api/sessions/sess-1'),
      ]);
      expect(results.every(r => r.status === 'rejected')).toBe(true);
      expect(mockGenerateSessionKeypair).toHaveBeenCalledTimes(1);

      // Two more real attempts remain before the cap trips
      await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');
      await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');
      const err = (await onUnauthorized('GET', '/api/devices').catch(e => e)) as GhostIDError;
      expect(err.code).toBe('NO_KEYS');
      expect(mockGenerateSessionKeypair).toHaveBeenCalledTimes(3);
    });

    it('resets the failure count after a successful restore', async () => {
      await withSession();
      const onUnauthorized = capturedOnUnauthorized();

      mockGenerateSessionKeypair
        .mockRejectedValueOnce(new Error('restore failed'))
        .mockRejectedValueOnce(new Error('restore failed'));
      await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');
      await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');

      stubRestoreSuccess();
      await onUnauthorized('GET', '/api/devices');

      // Three more real attempts are allowed, proving the count was reset
      mockGenerateSessionKeypair.mockRejectedValue(new Error('restore failed'));
      for (let i = 0; i < 3; i++) {
        await expect(onUnauthorized('GET', '/api/devices')).rejects.toThrow('restore failed');
      }
    });
  });

  describe('restoreSession', () => {
    it('throws NOT_INITIALIZED before init()', async () => {
      const g = sdk();
      await expect(g.restoreSession()).rejects.toThrow(GhostIDError);
    });

    function stubRestoreMocks(serverResult: 'success' | 'failure') {
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      if (serverResult === 'success') {
        mockRestoreSession.mockResolvedValue({
          sessionId: 'sess-old',
          userId: 'user-1',
          deviceId: 'device-1',
          expiresAt: Date.now() + 3_600_000,
        });
      } else {
        mockRestoreSession.mockRejectedValue(new Error('gone'));
      }
    }

    it('always attempts restore regardless of local state', async () => {
      stubRestoreMocks('success');
      const g = initializedSdk();
      await g.restoreSession();
      expect(mockRestoreSession).toHaveBeenCalledWith('restore-binding');
    });

    it('sets session from server response on success', async () => {
      stubRestoreMocks('success');
      const g = initializedSdk();
      await g.restoreSession();
      expect(g.getSession()).toMatchObject({ sessionId: 'sess-old', userId: 'user-1' });
    });

    it('signs the JWS with a random nonce as sessionChallenge', async () => {
      stubRestoreMocks('success');
      const g = initializedSdk();
      await g.restoreSession();
      const [claims, ,] = mockSignSessionBindingJWS.mock.calls[0];
      expect(typeof claims.sessionChallenge).toBe('string');
      expect(claims.sessionChallenge.length).toBeGreaterThan(0);
    });

    it('converts a 401 API error to NO_ACTIVE_SESSION GhostIDError', async () => {
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      mockRestoreSession.mockRejectedValue(
        new GhostIDError('unauthorized', ErrorCodes.API_ERROR, undefined, 401)
      );

      const err = await initializedSdk()
        .restoreSession()
        .catch(e => e);
      expect(err).toBeInstanceOf(GhostIDError);
      expect((err as GhostIDError).message).toContain('No active session');
    });

    it('rethrows non-401 errors unchanged', async () => {
      mockGenerateSessionKeypair.mockResolvedValue({
        privateKey: SESSION_PRIVATE_KEY,
        publicKey: SESSION_PUBLIC_KEY,
      });
      mockSignSessionBindingJWS.mockResolvedValue('restore-binding');
      mockRestoreSession.mockRejectedValue(new Error('network error'));

      const err = await initializedSdk()
        .restoreSession()
        .catch(e => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(GhostIDError);
      expect(err.message).toBe('network error');
    });

    it('leaves session null when restore fails', async () => {
      stubRestoreMocks('failure');
      const g = initializedSdk();
      await expect(g.restoreSession()).rejects.toThrow();
      expect(g.getSession()).toBeNull();
    });
  });

  describe('init', () => {
    it('enables guarded methods synchronously without awaiting', async () => {
      const g = sdk();
      await expect(g.logout()).rejects.toThrow(GhostIDError);
      g.init();
      await expect(g.logout()).resolves.toBeUndefined();
    });

    it('is idempotent and safe to call multiple times', async () => {
      const g = sdk();
      g.init();
      g.init();
      g.init();
      await expect(g.logout()).resolves.toBeUndefined();
    });
  });

  describe('guessDeviceName fallback', () => {
    it('uses "Unknown Device" when navigator is undefined', async () => {
      stubCreateIdentityMocks();
      vi.stubGlobal('navigator', undefined);
      const g = new GhostID({ backendUrl: 'http://localhost' });
      g.init();
      await g.createIdentity();
      vi.unstubAllGlobals();

      expect(mockRegisterDevice).toHaveBeenCalledWith(
        expect.objectContaining({ deviceName: 'Unknown Device' })
      );
    });

    it('uses matched UA hint when userAgent is recognised', async () => {
      stubCreateIdentityMocks();
      vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)' });
      const g = new GhostID({ backendUrl: 'http://localhost' });
      g.init();
      await g.createIdentity();
      vi.unstubAllGlobals();

      expect(mockRegisterDevice).toHaveBeenCalledWith(
        expect.objectContaining({ deviceName: 'iPhone' })
      );
    });
  });
});

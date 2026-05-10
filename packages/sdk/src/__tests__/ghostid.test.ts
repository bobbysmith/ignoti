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
    };
    static signRequest = mockApiClientSignRequest;
    static verifyRequest = vi.fn();
  }
  return { ApiClient, createApiClient: () => new ApiClient() };
});

const ROOT_PRIVATE_KEY = new Uint8Array(32).fill(1);
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
  mockGenerateMnemonic.mockReturnValue('word '.repeat(12).trim());
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

      expect(result.mnemonic).toBeTruthy();
      expect(result.userId).toBe('user-1');
      expect(result.deviceId).toBe('device-1');
      expect(mockRegisterUser).toHaveBeenCalledWith({ rootPublicKey: 'root-pub-b64' });
      expect(mockCreatePasskey).toHaveBeenCalled();
      expect(mockRegisterDevice).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', rootSignature: 'root-sig' })
      );
    });

    it('zeroes root private key even when registerDevice throws', async () => {
      stubCreateIdentityMocks();
      mockRegisterDevice.mockRejectedValue(new Error('network'));
      const rootKey = new Uint8Array(32).fill(1);
      mockDeriveRootKeys.mockResolvedValue({
        signing: { privateKey: rootKey, publicKey: ROOT_PUBLIC_KEY },
      });

      await expect(initializedSdk().createIdentity()).rejects.toThrow('network');
      expect(rootKey.every(b => b === 0)).toBe(true);
    });
  });

  describe('login', () => {
    it('sets active session on success', async () => {
      const info = stubLoginMocks();
      const g = initializedSdk();
      const result = await g.login();

      expect(result.sessionId).toBe(info.sessionId);
      expect(result.expiresAt).toBe(info.expiresAt);
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
        'sig-abc'
      );
      expect(g.getSession()).toBeNull();
    });

    it('throws and leaves session intact when server revocation fails', async () => {
      const { g } = await withSession();
      mockRevokeSession.mockRejectedValue(new Error('network'));
      await expect(g.logout()).rejects.toThrow('network');
      expect(g.getSession()).not.toBeNull();
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
  });

  describe('getSessionHeaders', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.getSessionHeaders()).rejects.toThrow(GhostIDError);
    });

    it('throws EXPIRED_CHALLENGE and logs out when session is expired', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      await expect(g.getSessionHeaders()).rejects.toThrow('expired');
      expect(g.getSession()).toBeNull();
    });

    it('returns Authorization, Timestamp, and Signature headers', async () => {
      const { g, sessionId } = await withSession();
      const headers = await g.getSessionHeaders();
      expect(headers.Authorization).toBe(`GhostID-Session ${sessionId}`);
      expect(headers['X-GhostID-Timestamp']).toMatch(/^\d+$/);
      expect(headers['X-GhostID-Signature']).toBe('sig-abc');
    });
  });

  describe('signWithSessionKey', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.signWithSessionKey({ foo: 1 })).rejects.toThrow(GhostIDError);
    });

    it('throws EXPIRED_CHALLENGE and logs out when session is expired', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      await expect(g.signWithSessionKey({ foo: 1 })).rejects.toThrow('expired');
      expect(g.getSession()).toBeNull();
    });

    it('returns signature from ApiClient.signRequest when session is valid', async () => {
      mockApiClientSignRequest.mockResolvedValue('signed-payload');
      const { g } = await withSession();
      expect(await g.signWithSessionKey({ foo: 'bar' })).toBe('signed-payload');
    });
  });

  describe('getDevices', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.getDevices()).rejects.toThrow(GhostIDError);
    });

    it('throws EXPIRED_CHALLENGE and logs out when session is expired', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      await expect(g.getDevices()).rejects.toThrow('expired');
      expect(g.getSession()).toBeNull();
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

    it('zeroes root key even when revokeDevice API throws', async () => {
      const g = initializedSdk();
      const rootKey = new Uint8Array(32).fill(1);
      mockDeriveRootKeys.mockResolvedValue({
        signing: { privateKey: rootKey, publicKey: ROOT_PUBLIC_KEY },
      });
      mockRevokeDevice.mockRejectedValue(new Error('network'));

      await expect(g.revokeDevice('device-1', MNEMONIC, 'user-1', 'cred-id')).rejects.toThrow(
        'network'
      );
      expect(rootKey.every(b => b === 0)).toBe(true);
    });
  });

  describe('getSessions', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.getSessions()).rejects.toThrow(GhostIDError);
    });

    it('throws EXPIRED_CHALLENGE and logs out when session is expired', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      await expect(g.getSessions()).rejects.toThrow('expired');
      expect(g.getSession()).toBeNull();
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
    });

    it('calls getSessions with correct session auth args', async () => {
      const { g, sessionId } = await withSession();
      mockGetSessions.mockResolvedValue({ sessions: [] });
      await g.getSessions();
      expect(mockGetSessions).toHaveBeenCalledWith(sessionId, expect.any(Number), 'sig-abc');
    });
  });

  describe('revokeSession', () => {
    it('throws NO_KEYS when no session', async () => {
      const g = initializedSdk();
      await expect(g.revokeSession('other-sess')).rejects.toThrow(GhostIDError);
    });

    it('throws EXPIRED_CHALLENGE and logs out when session is expired', async () => {
      const { g } = await withSession({ expiresAt: Date.now() - 1000 });
      await expect(g.revokeSession('other-sess')).rejects.toThrow('expired');
      expect(g.getSession()).toBeNull();
    });

    it('revokes another session without clearing local session', async () => {
      const { g, sessionId } = await withSession();
      mockRevokeSession.mockResolvedValue({ ok: true });
      await g.revokeSession('other-sess');
      expect(mockRevokeSession).toHaveBeenCalledWith(
        'other-sess',
        sessionId,
        expect.any(Number),
        'sig-abc'
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

    it('zeroes root key even when registerDevice throws during recovery', async () => {
      mockIsWebAuthnSupported.mockReturnValue(true);
      const rootKey = new Uint8Array(32).fill(1);
      mockDeriveRootKeys.mockResolvedValue({
        signing: { privateKey: rootKey, publicKey: ROOT_PUBLIC_KEY },
      });
      mockRecoverAccount.mockResolvedValue({ userId: 'user-1', options: makeOptions() });
      mockCreatePasskey.mockResolvedValue(makePasskeyResponse());
      mockRegisterDevice.mockRejectedValue(new Error('device fail'));

      await expect(initializedSdk().recoverIdentity('word '.repeat(12).trim())).rejects.toThrow(
        'device fail'
      );
      expect(rootKey.every(b => b === 0)).toBe(true);
    });
  });

  describe('destroy', () => {
    it('wipes session key, clears session, and resets initialized flag', async () => {
      const { g } = await withSession();
      g.destroy();

      expect(g.getSession()).toBeNull();
      await expect(g.logout()).rejects.toThrow(GhostIDError);
    });

    it('is safe to call when no session is active', () => {
      const g = initializedSdk();
      expect(() => g.destroy()).not.toThrow();
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

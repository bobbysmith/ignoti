import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createPasskey,
  getPasskeyAssertion,
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
} from '@/auth/passkey.ts';
import { IgnotiError } from '@/core/errors.ts';

function makeAttestationResponse(overrides = {}) {
  return {
    clientDataJSON: new Uint8Array([1, 2, 3]).buffer,
    attestationObject: new Uint8Array([4, 5, 6]).buffer,
    getTransports: () => ['internal'],
    ...overrides,
  };
}

function makeAssertionResponse(overrides = {}) {
  return {
    clientDataJSON: new Uint8Array([1]).buffer,
    authenticatorData: new Uint8Array([2]).buffer,
    signature: new Uint8Array([3]).buffer,
    userHandle: null,
    ...overrides,
  };
}

function makeCredential(response: object, overrides = {}) {
  return {
    id: 'cred-id',
    rawId: new Uint8Array([10, 11, 12]).buffer,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({}),
    response,
    ...overrides,
  };
}

describe('Auth passkey', () => {
  afterEach(() => vi.unstubAllGlobals());

  describe('isWebAuthnSupported', () => {
    it('returns false when window is undefined', () => {
      vi.stubGlobal('window', undefined);
      expect(isWebAuthnSupported()).toBe(false);
    });

    it('returns false when credentials is not in navigator', () => {
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', {});
      expect(isWebAuthnSupported()).toBe(false);
    });

    it('returns true when all APIs are present', () => {
      class PKC {}
      vi.stubGlobal('window', { PublicKeyCredential: PKC });
      vi.stubGlobal('navigator', { credentials: {} });
      expect(isWebAuthnSupported()).toBe(true);
    });
  });

  describe('isPlatformAuthenticatorAvailable', () => {
    it('returns false when WebAuthn is not supported', async () => {
      vi.stubGlobal('window', undefined);
      expect(await isPlatformAuthenticatorAvailable()).toBe(false);
    });

    it('returns false when PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable throws', async () => {
      const mockPublicKeyCredential = {
        isUserVerifyingPlatformAuthenticatorAvailable: () => Promise.reject(new Error('nope')),
      };
      vi.stubGlobal('window', { PublicKeyCredential: mockPublicKeyCredential });
      vi.stubGlobal('navigator', { credentials: {} });
      vi.stubGlobal('PublicKeyCredential', mockPublicKeyCredential);
      expect(await isPlatformAuthenticatorAvailable()).toBe(false);
    });
  });

  describe('createPasskey', () => {
    it('throws IgnotiError when window is undefined', async () => {
      vi.stubGlobal('window', undefined);
      await expect(createPasskey({} as never)).rejects.toThrow(IgnotiError);
    });

    it('throws IgnotiError when credentials.create returns null', async () => {
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(null) } });
      await expect(createPasskey({} as never)).rejects.toThrow(IgnotiError);
    });

    it('returns formatted response on success', async () => {
      const response = makeAttestationResponse();
      const cred = makeCredential(response);
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(cred) } });
      const result = await createPasskey({} as never);
      expect(result.id).toBe('cred-id');
      expect(typeof result.rawId).toBe('string');
      expect(result.type).toBe('public-key');
      expect(result.response.transports).toEqual(['internal']);
    });

    it('wraps unexpected errors as IgnotiError', async () => {
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', {
        credentials: { create: vi.fn().mockRejectedValue(new Error('hw error')) },
      });
      await expect(createPasskey({} as never)).rejects.toThrow(IgnotiError);
    });

    it('handles missing getTransports gracefully', async () => {
      const response = makeAttestationResponse({ getTransports: undefined });
      const cred = makeCredential(response);
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(cred) } });
      const result = await createPasskey({} as never);
      expect(result.response.transports).toBeUndefined();
    });

    it('handles missing authenticatorAttachment gracefully', async () => {
      const response = makeAttestationResponse();
      const cred = makeCredential(response, { authenticatorAttachment: undefined });
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(cred) } });
      const result = await createPasskey({} as never);
      expect(result.authenticatorAttachment).toBeUndefined();
    });
  });

  describe('getPasskeyAssertion', () => {
    it('throws IgnotiError when window is undefined', async () => {
      vi.stubGlobal('window', undefined);
      await expect(getPasskeyAssertion({} as never)).rejects.toThrow(IgnotiError);
    });

    it('throws IgnotiError when credentials.get returns null', async () => {
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(null) } });
      await expect(getPasskeyAssertion({} as never)).rejects.toThrow(IgnotiError);
    });

    it('returns formatted response on success', async () => {
      const response = makeAssertionResponse();
      const cred = makeCredential(response);
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } });
      const result = await getPasskeyAssertion({} as never);
      expect(result.id).toBe('cred-id');
      expect(typeof result.rawId).toBe('string');
      expect(result.response.userHandle).toBeNull();
    });

    it('encodes userHandle when present', async () => {
      const response = makeAssertionResponse({ userHandle: new Uint8Array([9, 8, 7]).buffer });
      const cred = makeCredential(response);
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } });
      const result = await getPasskeyAssertion({} as never);
      expect(typeof result.response.userHandle).toBe('string');
    });

    it('wraps unexpected errors as IgnotiError', async () => {
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', {
        credentials: { get: vi.fn().mockRejectedValue(new Error('cancelled')) },
      });
      await expect(getPasskeyAssertion({} as never)).rejects.toThrow(IgnotiError);
    });

    it('handles missing authenticatorAttachment gracefully', async () => {
      const response = makeAssertionResponse();
      const cred = makeCredential(response, { authenticatorAttachment: undefined });
      vi.stubGlobal('window', { PublicKeyCredential: class {} });
      vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } });
      const result = await getPasskeyAssertion({} as never);
      expect(result.authenticatorAttachment).toBeUndefined();
    });
  });
});

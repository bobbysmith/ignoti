import { describe, expect, it, vi } from 'vitest';
import { AuthApiClient } from '@/api/auth.ts';
import { VALIDATION } from '@/constants/index.ts';

function makeClient() {
  const makeRequest = vi.fn();
  return { client: new AuthApiClient(makeRequest), makeRequest };
}

describe('AuthApiClient', () => {
  describe('registerUser', () => {
    it('calls makeRequest with trimmed rootPublicKey', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ userId: 'u1', options: {} });
      await client.registerUser({ rootPublicKey: '  abc123  ' });
      expect(makeRequest).toHaveBeenCalledWith(
        'POST',
        '/api/auth/register',
        expect.objectContaining({ rootPublicKey: 'abc123' })
      );
    });

    it('throws when rootPublicKey is empty', async () => {
      const { client } = makeClient();
      await expect(client.registerUser({ rootPublicKey: '' })).rejects.toThrow();
    });

    it('throws when rootPublicKey exceeds max length', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_PUBLIC_KEY_LENGTH + 1);
      await expect(client.registerUser({ rootPublicKey: long })).rejects.toThrow(
        'exceeds maximum length'
      );
    });
  });

  describe('registerDevice', () => {
    const validRegistrationResponse = {
      id: 'cred-id',
      rawId: 'raw-id',
      type: 'public-key' as const,
      clientExtensionResults: {},
      response: { clientDataJSON: 'cdj', attestationObject: 'ao' },
    };

    it('calls makeRequest with validated fields', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ deviceId: 'd1', credentialId: 'cred-id' });
      await client.registerDevice({
        userId: 'user-1',
        registrationResponse: validRegistrationResponse,
        rootSignature: 'sig123',
        deviceName: 'My Device',
      });
      expect(makeRequest).toHaveBeenCalledWith(
        'POST',
        '/api/auth/register/device',
        expect.objectContaining({ userId: 'user-1', rootSignature: 'sig123' })
      );
    });

    it('throws when registrationResponse is missing', async () => {
      const { client } = makeClient();
      await expect(
        client.registerDevice({
          userId: 'u1',
          registrationResponse: null as never,
          rootSignature: 'sig',
        })
      ).rejects.toThrow();
    });
  });

  describe('requestChallenge', () => {
    it('calls makeRequest with POST and empty body', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ options: {} });
      await client.requestChallenge();
      expect(makeRequest).toHaveBeenCalledWith('POST', '/api/auth/challenge', {});
    });
  });

  describe('login', () => {
    it('calls makeRequest with the assertion', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ sessionChallenge: 'ch', deviceId: 'd1' });
      const assertion = { id: 'cred', type: 'public-key' } as never;
      await client.login({ assertion });
      expect(makeRequest).toHaveBeenCalledWith(
        'POST',
        '/api/auth/login',
        expect.objectContaining({ assertion })
      );
    });

    it('throws when assertion is missing', async () => {
      const { client } = makeClient();
      await expect(client.login({ assertion: null as never })).rejects.toThrow();
    });
  });

  describe('createSession', () => {
    it('calls makeRequest with trimmed sessionBinding', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ sessionId: 's1', expiresAt: 0, userId: 'u1' });
      await client.createSession({ sessionBinding: '  binding123  ' });
      expect(makeRequest).toHaveBeenCalledWith('POST', '/api/auth/session', {
        sessionBinding: 'binding123',
      });
    });

    it('throws when sessionBinding exceeds MAX_SESSION_BINDING_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SESSION_BINDING_LENGTH + 1);
      await expect(client.createSession({ sessionBinding: long })).rejects.toThrow(
        'exceeds maximum length'
      );
    });
  });

  describe('restoreSession', () => {
    it('calls makeRequest with trimmed sessionBinding', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({
        sessionId: 's1',
        userId: 'u1',
        deviceId: 'd1',
        expiresAt: 0,
      });
      await client.restoreSession('  binding123  ');
      expect(makeRequest).toHaveBeenCalledWith('POST', '/api/auth/session/restore', {
        sessionBinding: 'binding123',
      });
    });

    it('throws when sessionBinding is empty', async () => {
      const { client } = makeClient();
      await expect(client.restoreSession('')).rejects.toThrow();
    });

    it('throws when sessionBinding exceeds MAX_SESSION_BINDING_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SESSION_BINDING_LENGTH + 1);
      await expect(client.restoreSession(long)).rejects.toThrow('exceeds maximum length');
    });
  });

  describe('recoverAccount', () => {
    it('calls makeRequest with rootPublicKey', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ userId: 'u1', options: {} });
      await client.recoverAccount({ rootPublicKey: 'pubkey123' });
      expect(makeRequest).toHaveBeenCalledWith('POST', '/api/auth/recover', {
        rootPublicKey: 'pubkey123',
      });
    });

    it('throws when rootPublicKey is empty', async () => {
      const { client } = makeClient();
      await expect(client.recoverAccount({ rootPublicKey: '' })).rejects.toThrow();
    });
  });
});

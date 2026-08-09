import { describe, expect, it, vi } from 'vitest';
import { SessionsApiClient } from '@/api/sessions.ts';
import { VALIDATION } from '@/constants/index.ts';

function makeClient() {
  const makeRequest = vi.fn();
  return { client: new SessionsApiClient(makeRequest), makeRequest };
}

const SESSION_ID = 'session-uuid-1234';
const TARGET_SESSION_ID = 'session-uuid-5678';
const IAT = 1700000000;
const SIGNATURE = 'sig-abc';
const JTI = 'nonce-uuid-abcd';

describe('SessionsApiClient', () => {
  describe('getSessions', () => {
    it('calls makeRequest with correct method and path', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ sessions: [] });
      await client.getSessions(SESSION_ID, IAT, SIGNATURE, JTI);
      expect(makeRequest).toHaveBeenCalledWith(
        'GET',
        '/api/sessions',
        undefined,
        expect.any(Object)
      );
    });

    it('sends session auth headers', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ sessions: [] });
      await client.getSessions(SESSION_ID, IAT, SIGNATURE, JTI);
      const headers = makeRequest.mock.calls[0][3];
      expect(headers).toMatchObject({
        Authorization: expect.stringContaining(SESSION_ID),
        'X-Ignoti-Timestamp': String(IAT),
        'X-Ignoti-Signature': SIGNATURE,
      });
    });

    it('returns the response from makeRequest', async () => {
      const { client, makeRequest } = makeClient();
      const mockResponse = { sessions: [{ id: SESSION_ID, deviceId: 'dev-1' }] };
      makeRequest.mockResolvedValue(mockResponse);
      await expect(client.getSessions(SESSION_ID, IAT, SIGNATURE, JTI)).resolves.toEqual(
        mockResponse
      );
    });

    it('throws when sessionId is empty', async () => {
      const { client } = makeClient();
      await expect(client.getSessions('', IAT, SIGNATURE, JTI)).rejects.toThrow();
    });

    it('throws when signature is empty', async () => {
      const { client } = makeClient();
      await expect(client.getSessions(SESSION_ID, IAT, '', JTI)).rejects.toThrow();
    });

    it('throws when sessionId exceeds MAX_SESSION_TOKEN_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SESSION_TOKEN_LENGTH + 1);
      await expect(client.getSessions(long, IAT, SIGNATURE, JTI)).rejects.toThrow(
        'exceeds maximum length'
      );
    });

    it('throws when signature exceeds MAX_SIGNATURE_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SIGNATURE_LENGTH + 1);
      await expect(client.getSessions(SESSION_ID, IAT, long, JTI)).rejects.toThrow(
        'exceeds maximum length'
      );
    });
  });

  describe('revokeSession', () => {
    it('calls makeRequest with DELETE and targetSessionId in path', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ ok: true });
      await client.revokeSession(TARGET_SESSION_ID, SESSION_ID, IAT, SIGNATURE, JTI);
      expect(makeRequest).toHaveBeenCalledWith(
        'DELETE',
        expect.stringContaining(TARGET_SESSION_ID),
        undefined,
        expect.any(Object)
      );
    });

    it('sends session auth headers using currentSessionId', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ ok: true });
      await client.revokeSession(TARGET_SESSION_ID, SESSION_ID, IAT, SIGNATURE, JTI);
      const headers = makeRequest.mock.calls[0][3];
      expect(headers).toMatchObject({
        Authorization: expect.stringContaining(SESSION_ID),
        'X-Ignoti-Timestamp': String(IAT),
        'X-Ignoti-Signature': SIGNATURE,
      });
    });

    it('returns { ok: true } on success', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ ok: true });
      await expect(
        client.revokeSession(TARGET_SESSION_ID, SESSION_ID, IAT, SIGNATURE, JTI)
      ).resolves.toEqual({ ok: true });
    });

    it('throws when targetSessionId is empty', async () => {
      const { client } = makeClient();
      await expect(client.revokeSession('', SESSION_ID, IAT, SIGNATURE, JTI)).rejects.toThrow();
    });

    it('throws when currentSessionId is empty', async () => {
      const { client } = makeClient();
      await expect(
        client.revokeSession(TARGET_SESSION_ID, '', IAT, SIGNATURE, JTI)
      ).rejects.toThrow();
    });

    it('throws when signature is empty', async () => {
      const { client } = makeClient();
      await expect(
        client.revokeSession(TARGET_SESSION_ID, SESSION_ID, IAT, '', JTI)
      ).rejects.toThrow();
    });

    it('throws when targetSessionId exceeds MAX_SESSION_TOKEN_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SESSION_TOKEN_LENGTH + 1);
      await expect(client.revokeSession(long, SESSION_ID, IAT, SIGNATURE, JTI)).rejects.toThrow(
        'exceeds maximum length'
      );
    });

    it('throws when currentSessionId exceeds MAX_SESSION_TOKEN_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SESSION_TOKEN_LENGTH + 1);
      await expect(
        client.revokeSession(TARGET_SESSION_ID, long, IAT, SIGNATURE, JTI)
      ).rejects.toThrow('exceeds maximum length');
    });

    it('throws when signature exceeds MAX_SIGNATURE_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SIGNATURE_LENGTH + 1);
      await expect(
        client.revokeSession(TARGET_SESSION_ID, SESSION_ID, IAT, long, JTI)
      ).rejects.toThrow('exceeds maximum length');
    });
  });

  describe('revokeAllSessions', () => {
    it('calls makeRequest with DELETE on the sessions list endpoint', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ revoked: 2 });
      await client.revokeAllSessions(SESSION_ID, IAT, SIGNATURE, JTI);
      expect(makeRequest).toHaveBeenCalledWith(
        'DELETE',
        '/api/sessions',
        undefined,
        expect.any(Object)
      );
    });

    it('sends session auth headers', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ revoked: 1 });
      await client.revokeAllSessions(SESSION_ID, IAT, SIGNATURE, JTI);
      const headers = makeRequest.mock.calls[0][3];
      expect(headers).toMatchObject({
        Authorization: expect.stringContaining(SESSION_ID),
        'X-Ignoti-Nonce': JTI,
        'X-Ignoti-Timestamp': String(IAT),
        'X-Ignoti-Signature': SIGNATURE,
      });
    });

    it('returns { revoked: N } on success', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ revoked: 5 });
      await expect(client.revokeAllSessions(SESSION_ID, IAT, SIGNATURE, JTI)).resolves.toEqual({
        revoked: 5,
      });
    });

    it('throws when sessionId is empty', async () => {
      const { client } = makeClient();
      await expect(client.revokeAllSessions('', IAT, SIGNATURE, JTI)).rejects.toThrow();
    });

    it('throws when signature is empty', async () => {
      const { client } = makeClient();
      await expect(client.revokeAllSessions(SESSION_ID, IAT, '', JTI)).rejects.toThrow();
    });
  });
});

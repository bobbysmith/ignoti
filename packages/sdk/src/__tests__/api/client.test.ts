import { describe, expect, it } from 'vitest';
import { ApiClient, createApiClient } from '@/api/client.ts';
import { generateSessionSigningKeypair } from '@/core/crypto.ts';

const BASE_URL = 'http://localhost:3000';
const SESSION_ID = 'abc';

describe('client', () => {
  describe('createApiClient', () => {
    it('returns an ApiClient instance', () => {
      expect(createApiClient({ baseUrl: BASE_URL })).toBeInstanceOf(ApiClient);
    });
  });

  describe('ApiClient', () => {
    it('exposes auth and devices sub-clients', () => {
      const client = new ApiClient({ baseUrl: BASE_URL });
      expect(client.auth).toBeDefined();
      expect(client.devices).toBeDefined();
    });

    describe('signRequest', () => {
      it('returns a base64url signature', () => {
        const { privateKey } = generateSessionSigningKeypair();
        const sig = ApiClient.signRequest({ sessionId: SESSION_ID, iat: 1 }, privateKey);
        expect(typeof sig).toBe('string');
        expect(sig).not.toMatch(/[+/=]/);
      });
    });

    describe('verifyRequest', () => {
      it('verifies a signature produced by signRequest', () => {
        const { publicKey, privateKey } = generateSessionSigningKeypair();
        const payload = { sessionId: SESSION_ID, iat: 1 };
        const sig = ApiClient.signRequest(payload, privateKey);
        expect(ApiClient.verifyRequest(payload, sig, publicKey)).toBe(true);
      });

      it('returns false for a tampered payload', () => {
        const { publicKey, privateKey } = generateSessionSigningKeypair();
        const sig = ApiClient.signRequest({ sessionId: SESSION_ID, iat: 1 }, privateKey);
        expect(ApiClient.verifyRequest({ sessionId: 'xyz', iat: 1 }, sig, publicKey)).toBe(false);
      });
    });
  });
});

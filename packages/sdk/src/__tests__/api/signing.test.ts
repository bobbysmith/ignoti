import { describe, expect, it, vi } from 'vitest';
import { signRequest, verifyRequest } from '@/api/signing.ts';
import { generateSessionSigningKeypair } from '@/core/crypto.ts';
import { GhostIDError } from '@/core/errors.ts';

describe('signing', () => {
  describe('signRequest / verifyRequest', () => {
    it('produces a base64url signature that verifies', async () => {
      const { publicKey, privateKey } = await generateSessionSigningKeypair();
      const payload = { sessionId: 'abc', iat: 1234567890 };
      const sig = await signRequest(payload, privateKey);
      expect(typeof sig).toBe('string');
      expect(sig).not.toMatch(/[+/=]/);
      expect(await verifyRequest(payload, sig, publicKey)).toBe(true);
    });

    it('fails verification when payload is tampered', async () => {
      const { publicKey, privateKey } = await generateSessionSigningKeypair();
      const sig = await signRequest({ sessionId: 'abc', iat: 1 }, privateKey);
      expect(await verifyRequest({ sessionId: 'xyz', iat: 1 }, sig, publicKey)).toBe(false);
    });

    it('fails verification with wrong public key', async () => {
      const kp1 = await generateSessionSigningKeypair();
      const kp2 = await generateSessionSigningKeypair();
      const sig = await signRequest({ x: 1 }, kp1.privateKey);
      expect(await verifyRequest({ x: 1 }, sig, kp2.publicKey)).toBe(false);
    });

    it('verifyRequest trims whitespace from signature', async () => {
      const { publicKey, privateKey } = await generateSessionSigningKeypair();
      const payload = { a: 1 };
      const sig = await signRequest(payload, privateKey);
      expect(await verifyRequest(payload, `  ${sig}  `, publicKey)).toBe(true);
    });
  });

  describe('signRequest validation', () => {
    it('throws for null payload', async () => {
      const { privateKey } = await generateSessionSigningKeypair();
      await expect(
        signRequest(null as unknown as Record<string, unknown>, privateKey)
      ).rejects.toThrow();
    });

    it('wraps unexpected sign errors as GhostIDError (catch branch)', async () => {
      const { privateKey } = await generateSessionSigningKeypair();
      vi.spyOn(crypto.subtle, 'sign').mockRejectedValueOnce(new Error('hw failure'));
      await expect(signRequest({ x: 1 }, privateKey)).rejects.toBeInstanceOf(GhostIDError);
    });
  });

  describe('verifyRequest validation', () => {
    it('returns false for null payload', async () => {
      const { publicKey } = await generateSessionSigningKeypair();
      expect(
        await verifyRequest(null as unknown as Record<string, unknown>, 'sig', publicKey)
      ).toBe(false);
    });

    it('returns false for empty signature', async () => {
      const { publicKey } = await generateSessionSigningKeypair();
      expect(await verifyRequest({ x: 1 }, '', publicKey)).toBe(false);
    });

    it('returns false when verify throws internally (catch branch)', async () => {
      const { publicKey, privateKey } = await generateSessionSigningKeypair();
      const payload = { x: 1 };
      const sig = await signRequest(payload, privateKey);
      vi.spyOn(crypto.subtle, 'verify').mockRejectedValueOnce(new Error('hw failure'));
      expect(await verifyRequest(payload, sig, publicKey)).toBe(false);
    });
  });
});

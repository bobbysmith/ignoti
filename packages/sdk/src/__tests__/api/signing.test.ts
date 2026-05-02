import { describe, expect, it, vi } from 'vitest';
import { signRequest, verifyRequest } from '@/api/signing.ts';
import { generateSessionSigningKeypair } from '@/core/crypto.ts';
import { GhostIDError } from '@/core/errors.ts';

const { mockSign, mockVerify } = vi.hoisted(() => ({
  mockSign: vi.fn(),
  mockVerify: vi.fn(),
}));

vi.mock('@/core/crypto.ts', async importOriginal => {
  const mod = await importOriginal<typeof import('@/core/crypto.ts')>();
  mockSign.mockImplementation(mod.sign);
  mockVerify.mockImplementation(mod.verify);
  return { ...mod, sign: mockSign, verify: mockVerify };
});

describe('signing', () => {
  describe('signRequest / verifyRequest', () => {
    it('produces a base64url signature that verifies', () => {
      const { publicKey, privateKey } = generateSessionSigningKeypair();
      const payload = { sessionId: 'abc', iat: 1234567890 };
      const sig = signRequest(payload, privateKey);
      expect(typeof sig).toBe('string');
      expect(sig).not.toMatch(/[+/=]/);
      expect(verifyRequest(payload, sig, publicKey)).toBe(true);
    });

    it('fails verification when payload is tampered', () => {
      const { publicKey, privateKey } = generateSessionSigningKeypair();
      const sig = signRequest({ sessionId: 'abc', iat: 1 }, privateKey);
      expect(verifyRequest({ sessionId: 'xyz', iat: 1 }, sig, publicKey)).toBe(false);
    });

    it('fails verification with wrong public key', () => {
      const kp1 = generateSessionSigningKeypair();
      const kp2 = generateSessionSigningKeypair();
      const sig = signRequest({ x: 1 }, kp1.privateKey);
      expect(verifyRequest({ x: 1 }, sig, kp2.publicKey)).toBe(false);
    });

    it('verifyRequest trims whitespace from signature', () => {
      const { publicKey, privateKey } = generateSessionSigningKeypair();
      const payload = { a: 1 };
      const sig = signRequest(payload, privateKey);
      expect(verifyRequest(payload, `  ${sig}  `, publicKey)).toBe(true);
    });
  });

  describe('signRequest validation', () => {
    it('throws for null payload', () => {
      const { privateKey } = generateSessionSigningKeypair();
      expect(() => signRequest(null as unknown as Record<string, unknown>, privateKey)).toThrow();
    });

    it('throws for empty private key', () => {
      expect(() => signRequest({ x: 1 }, new Uint8Array(0))).toThrow();
    });

    it('wraps unexpected sign errors as GhostIDError (catch branch)', () => {
      const { privateKey } = generateSessionSigningKeypair();
      mockSign.mockImplementationOnce(() => {
        throw new Error('hw failure');
      });
      expect(() => signRequest({ x: 1 }, privateKey)).toThrow(GhostIDError);
    });
  });

  describe('verifyRequest validation', () => {
    it('returns false for null payload', () => {
      const { publicKey } = generateSessionSigningKeypair();
      expect(verifyRequest(null as unknown as Record<string, unknown>, 'sig', publicKey)).toBe(
        false
      );
    });

    it('returns false for empty signature', () => {
      const { publicKey } = generateSessionSigningKeypair();
      expect(verifyRequest({ x: 1 }, '', publicKey)).toBe(false);
    });

    it('returns false for empty public key', () => {
      expect(verifyRequest({ x: 1 }, 'sig', new Uint8Array(0))).toBe(false);
    });

    it('returns false when verify throws internally (catch branch)', () => {
      const { publicKey, privateKey } = generateSessionSigningKeypair();
      const payload = { x: 1 };
      const sig = signRequest(payload, privateKey);
      mockVerify.mockImplementationOnce(() => {
        throw new Error('hw failure');
      });
      expect(verifyRequest(payload, sig, publicKey)).toBe(false);
    });
  });
});

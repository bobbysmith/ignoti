import { describe, expect, it, vi } from 'vitest';
import {
  base64UrlToBuffer,
  bufferToBase64Url,
  constantTimeEqual,
  deriveRootKeysFromMnemonic,
  fromBase64,
  generateMnemonic,
  generateNonce,
  generateSessionSigningKeypair,
  hash,
  sign,
  stringToBytes,
  toBase64,
  validateMnemonic,
  verify,
} from '@/core/crypto.ts';
import { ErrorCodes, GhostIDError } from '@/core/errors.ts';

const { mockMnemonicToSeed } = vi.hoisted(() => ({ mockMnemonicToSeed: vi.fn() }));

vi.mock('@scure/bip39', async importOriginal => {
  const mod = await importOriginal<typeof import('@scure/bip39')>();
  mockMnemonicToSeed.mockImplementation(mod.mnemonicToSeed);
  return { ...mod, mnemonicToSeed: mockMnemonicToSeed };
});

describe('crypto', () => {
  describe('generateMnemonic / validateMnemonic', () => {
    it('generates a valid 12-word mnemonic', () => {
      const m = generateMnemonic();
      expect(m.split(' ').length).toBe(12);
      expect(validateMnemonic(m)).toBe(true);
    });

    it('rejects invalid mnemonics', () => {
      expect(validateMnemonic('not a valid mnemonic at all here now')).toBe(false);
      expect(validateMnemonic('')).toBe(false);
    });
  });

  describe('deriveRootKeysFromMnemonic', () => {
    it('derives deterministic 32-byte Ed25519 keypair', async () => {
      const mnemonic = generateMnemonic();
      const ks1 = await deriveRootKeysFromMnemonic(mnemonic);
      const ks2 = await deriveRootKeysFromMnemonic(mnemonic);
      expect(ks1.signing.publicKey).toHaveLength(32);
      expect(ks1.signing.privateKey).toHaveLength(32);
      expect(ks1.signing.publicKey).toEqual(ks2.signing.publicKey);
      expect(ks1.signing.privateKey).toEqual(ks2.signing.privateKey);
      expect(ks1.version).toBe(1);
    });

    it('different mnemonics produce different keys', async () => {
      const ks1 = await deriveRootKeysFromMnemonic(generateMnemonic());
      const ks2 = await deriveRootKeysFromMnemonic(generateMnemonic());
      expect(ks1.signing.publicKey).not.toEqual(ks2.signing.publicKey);
    });

    it('different versions produce different keys from the same mnemonic', async () => {
      const mnemonic = generateMnemonic();
      const ks1 = await deriveRootKeysFromMnemonic(mnemonic, 1);
      const ks2 = await deriveRootKeysFromMnemonic(mnemonic, 2);
      expect(ks1.signing.publicKey).not.toEqual(ks2.signing.publicKey);
    });

    it('throws on invalid mnemonic', async () => {
      await expect(deriveRootKeysFromMnemonic('bad mnemonic')).rejects.toThrow();
    });

    it('wraps unexpected internal errors as GhostIDError (catch branch)', async () => {
      mockMnemonicToSeed.mockRejectedValueOnce(new Error('internal failure'));
      await expect(deriveRootKeysFromMnemonic(generateMnemonic())).rejects.toBeInstanceOf(
        GhostIDError
      );
    });

    it('re-throws GhostIDError unchanged when thrown inside try (catch branch)', async () => {
      const original = new GhostIDError('already wrapped', ErrorCodes.CRYPTOGRAPHY_ERROR);
      mockMnemonicToSeed.mockRejectedValueOnce(original);
      const thrown = await deriveRootKeysFromMnemonic(generateMnemonic()).catch(e => e);
      expect(thrown).toBe(original);
    });
  });

  describe('sign / verify', () => {
    it('produces a 64-byte signature that verifies', async () => {
      const { signing } = await deriveRootKeysFromMnemonic(generateMnemonic());
      const message = stringToBytes('hello world');
      const sig = sign(message, signing.privateKey);
      expect(sig).toHaveLength(64);
      expect(verify(sig, message, signing.publicKey)).toBe(true);
    });

    it('rejects a tampered message', async () => {
      const { signing } = await deriveRootKeysFromMnemonic(generateMnemonic());
      const sig = sign(stringToBytes('original'), signing.privateKey);
      expect(verify(sig, stringToBytes('tampered'), signing.publicKey)).toBe(false);
    });

    it('rejects a wrong public key', async () => {
      const ks1 = await deriveRootKeysFromMnemonic(generateMnemonic());
      const ks2 = await deriveRootKeysFromMnemonic(generateMnemonic());
      const sig = sign(stringToBytes('msg'), ks1.signing.privateKey);
      expect(verify(sig, stringToBytes('msg'), ks2.signing.publicKey)).toBe(false);
    });

    it('verify returns false on zeroed signature without throwing', async () => {
      const { signing } = await deriveRootKeysFromMnemonic(generateMnemonic());
      expect(verify(new Uint8Array(64), stringToBytes('msg'), signing.publicKey)).toBe(false);
    });

    it('verify returns false when ed25519.verify throws (wrong-length public key)', () => {
      expect(verify(new Uint8Array(64), stringToBytes('msg'), new Uint8Array(16))).toBe(false);
    });
  });

  describe('generateSessionSigningKeypair', () => {
    it('returns a CryptoKeyPair with non-extractable private key', async () => {
      const kp = await generateSessionSigningKeypair();
      expect(kp.privateKey).toBeInstanceOf(CryptoKey);
      expect(kp.publicKey).toBeInstanceOf(CryptoKey);
      expect(kp.privateKey.type).toBe('private');
      expect(kp.publicKey.type).toBe('public');
      expect(kp.privateKey.extractable).toBe(false);
      expect(kp.publicKey.extractable).toBe(true);
    });

    it('private key supports sign, public key supports verify', async () => {
      const kp = await generateSessionSigningKeypair();
      expect(kp.privateKey.usages).toContain('sign');
      expect(kp.publicKey.usages).toContain('verify');
    });

    it('generates fresh keys on each call', async () => {
      const a = await generateSessionSigningKeypair();
      const b = await generateSessionSigningKeypair();
      const msg = new TextEncoder().encode('test');
      const sigA = await crypto.subtle.sign('Ed25519', a.privateKey, msg);
      const sigB = await crypto.subtle.sign('Ed25519', b.privateKey, msg);
      expect(new Uint8Array(sigA)).not.toEqual(new Uint8Array(sigB));
    });
  });

  describe('toBase64 / fromBase64', () => {
    it('round-trips arbitrary bytes', () => {
      const bytes = new Uint8Array([0, 1, 2, 255, 128, 64]);
      expect(fromBase64(toBase64(bytes))).toEqual(bytes);
    });

    it('produces base64url with no +, /, or = characters', () => {
      const bytes = new Uint8Array(64).fill(0xfe);
      expect(toBase64(bytes)).not.toMatch(/[+/=]/);
    });
  });

  describe('bufferToBase64Url / base64UrlToBuffer', () => {
    it('round-trips an ArrayBuffer', () => {
      const buf = new Uint8Array([10, 20, 30, 40]).buffer;
      const decoded = base64UrlToBuffer(bufferToBase64Url(buf));
      expect(new Uint8Array(decoded)).toEqual(new Uint8Array(buf));
    });
  });

  describe('generateNonce', () => {
    it('produces a non-empty base64url string', () => {
      const n = generateNonce();
      expect(typeof n).toBe('string');
      expect(n.length).toBeGreaterThan(0);
      expect(n).not.toMatch(/[+/=]/);
    });

    it('generates unique values', () => {
      expect(generateNonce()).not.toBe(generateNonce());
    });
  });

  describe('hash', () => {
    it('produces a 32-byte deterministic output', () => {
      const input = stringToBytes('ghostid');
      expect(hash(input)).toHaveLength(32);
      expect(hash(input)).toEqual(hash(input));
    });

    it('different inputs produce different hashes', () => {
      expect(hash(stringToBytes('a'))).not.toEqual(hash(stringToBytes('b')));
    });
  });

  describe('constantTimeEqual', () => {
    it('returns true for equal arrays', () => {
      expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    });

    it('returns false for different content', () => {
      expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    });

    it('returns false for different lengths', () => {
      expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    });
  });
});

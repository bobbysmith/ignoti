/**
 * @file crypto.ts
 * Crypto primitives backed by audited, ESM-native libraries:
 *   - `@noble/curves/ed25519` - Ed25519 sign/verify/keygen
 *   - `@noble/hashes/blake2`  - BLAKE2b hashing
 *   - Web Crypto              - random bytes, UTF-8
 *
 * Conventions:
 *   - Private/secret keys are the 32-byte Ed25519 seed (NOT the 64-byte
 *     libsodium-style sk||pk concatenation). `@noble`'s convention.
 *   - `toBase64`/`fromBase64`/`bufferToBase64Url`/`base64UrlToBuffer` all use
 *     base64url, no padding (RFC 4648 §5). The names are kept as-is to avoid
 *     churn at call sites; treat them as base64url-everywhere.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

import { CRYPTO, ERROR_MESSAGES } from '@/constants';
import type { RootKeySet } from '@/types';

import { ErrorCodes, GhostIDError } from './errors';

const textEncoder = new TextEncoder();

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(s: string): Uint8Array {
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = norm.length % 4 ? norm + '='.repeat(4 - (norm.length % 4)) : norm;
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export class CryptoUtils {
  static bufferToBase64Url(buffer: ArrayBuffer): string {
    return bytesToBase64Url(new Uint8Array(buffer));
  }

  static base64UrlToBuffer(base64Url: string): ArrayBuffer {
    const bytes = base64UrlToBytes(base64Url);
    const ab = new ArrayBuffer(bytes.length);
    new Uint8Array(ab).set(bytes);
    return ab;
  }

  /**
   * @param message
   * @param privateKey 32-byte Ed25519 seed
   */
  static sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return ed25519.sign(message, privateKey);
  }

  /** Returns 32-byte Ed25519 seed as `privateKey` and 32-byte public key. */
  static generateSessionSigningKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const { secretKey, publicKey } = ed25519.keygen();
    return { publicKey, privateKey: secretKey };
  }

  static stringToBytes(str: string): Uint8Array {
    return textEncoder.encode(str);
  }

  /** base64url, no padding. */
  static toBase64(bytes: Uint8Array): string {
    return bytesToBase64Url(bytes);
  }

  /** Accepts base64url (standard `+`/`/` is also tolerated). */
  static fromBase64(base64: string): Uint8Array {
    return base64UrlToBytes(base64);
  }

  static generateMnemonic(): string {
    return generateMnemonic(wordlist, 128);
  }

  static validateMnemonic(mnemonic: string): boolean {
    return validateMnemonic(mnemonic, wordlist);
  }

  /**
   * Derives an Ed25519 root keypair from a BIP39 mnemonic. The mnemonic is
   * stretched to a 64-byte seed by BIP39 (PBKDF2-HMAC-SHA512), then the first
   * `SIGNING_KEY_SIZE` bytes are domain-separated with a BLAKE2b keyed hash
   * (key = `ROOT_KEY_CONTEXT`) before being used as the Ed25519 seed.
   *
   * `version` is bound into the BLAKE2b personalization so future versions can
   * derive a fresh keyset from the same mnemonic without colliding.
   */
  static async deriveRootKeysFromMnemonic(mnemonic: string, version = 1): Promise<RootKeySet> {
    if (!CryptoUtils.validateMnemonic(mnemonic)) {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_MNEMONIC, ErrorCodes.INVALID_INPUT);
    }
    try {
      const seed = await mnemonicToSeed(mnemonic);
      const personal = textEncoder.encode(`v${version}`.padEnd(16, '\0')).slice(0, 16);
      const key = textEncoder.encode(CRYPTO.ROOT_KEY_CONTEXT.padEnd(64, '\0')).slice(0, 64);
      const signingSeed = blake2b(seed.slice(0, 32), {
        dkLen: CRYPTO.SIGNING_KEY_SIZE,
        key,
        personalization: personal,
      });
      const publicKey = ed25519.getPublicKey(signingSeed);

      CryptoUtils.secureWipe(seed);

      return {
        signing: {
          publicKey,
          privateKey: signingSeed,
        },
        version,
        createdAt: Date.now(),
      };
    } catch (error) {
      if (error instanceof GhostIDError) {
        throw error;
      }
      throw new GhostIDError(
        `${ERROR_MESSAGES.KEY_DERIVATION_FAILED}: ${(error as Error).message}`,
        ErrorCodes.INVALID_INPUT,
        error as Error
      );
    }
  }

  static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
    try {
      return ed25519.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  }

  /** Returns base64url of `length` cryptographically-random bytes. */
  static generateNonce(length = CRYPTO.NONCE_SIZE): string {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
  }

  /** BLAKE2b → `CRYPTO.HASH_SIZE` bytes. */
  static hash(data: Uint8Array): Uint8Array {
    return blake2b(data, { dkLen: CRYPTO.HASH_SIZE });
  }

  static constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
    return diff === 0;
  }

  /**
   * Best-effort wipe. JS engines may have already copied buffers; this is
   * defense-in-depth, not a guarantee.
   */
  static secureWipe(data: Uint8Array): void {
    if (data) {
      data.fill(0);
    }
  }
}

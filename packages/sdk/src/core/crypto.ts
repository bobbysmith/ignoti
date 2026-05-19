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
 *   - All base64 helpers use base64url, no padding (RFC 4648 §5).
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import {
  generateMnemonic as bip39GenerateMnemonic,
  validateMnemonic as bip39ValidateMnemonic,
  mnemonicToSeed,
} from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

import { CRYPTO, ERROR_MESSAGES } from '@/constants';
import type { RootKeySet } from '@/types';

import { ErrorCodes, GhostIDError } from './errors';

const textEncoder = new TextEncoder();

// Fixed DER header that wraps a 32-byte Ed25519 seed as PKCS8 for importKey.
// Structure: SEQUENCE { version=0, AlgorithmIdentifier { OID 1.3.101.112 }, OCTET STRING { seed } }
const ED25519_PKCS8_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function seedToCryptoKey(seed: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(ED25519_PKCS8_HEADER.length + seed.length);
  pkcs8.set(ED25519_PKCS8_HEADER);
  pkcs8.set(seed, ED25519_PKCS8_HEADER.length);
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
}

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

export function bufferToBase64Url(buffer: ArrayBuffer): string {
  return bytesToBase64Url(new Uint8Array(buffer));
}

export function base64UrlToBuffer(base64Url: string): ArrayBuffer {
  const bytes = base64UrlToBytes(base64Url);
  const ab = new ArrayBuffer(bytes.length);
  new Uint8Array(ab).set(bytes);
  return ab;
}

/**
 * @param message
 * @param privateKey 32-byte Ed25519 seed
 */
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/**
 * Generates a session signing keypair using WebCrypto.
 * The private key is non-extractable — its bytes never enter the JS heap.
 * The public key is exportable (public keys carry no secret).
 */
export async function generateSessionSigningKeypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
}

export function stringToBytes(str: string): Uint8Array {
  return textEncoder.encode(str);
}

/** base64url, no padding. */
export function toBase64(bytes: Uint8Array): string {
  return bytesToBase64Url(bytes);
}

/** Accepts base64url (standard `+`/`/` is also tolerated). */
export function fromBase64(base64: string): Uint8Array {
  return base64UrlToBytes(base64);
}

export function generateMnemonic(): string[] {
  return bip39GenerateMnemonic(wordlist, 128).split(' ');
}

export function validateMnemonic(mnemonic: string): boolean {
  return bip39ValidateMnemonic(mnemonic, wordlist);
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
export async function deriveRootKeysFromMnemonic(
  mnemonic: string,
  version = 1
): Promise<RootKeySet> {
  if (!validateMnemonic(mnemonic)) {
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
    const privateKey = await seedToCryptoKey(signingSeed);
    signingSeed.fill(0);
    seed.fill(0);

    return {
      signing: { publicKey, privateKey },
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

export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** Returns base64url of `length` cryptographically-random bytes. */
export function generateNonce(length = CRYPTO.NONCE_SIZE): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/** BLAKE2b → `CRYPTO.HASH_SIZE` bytes. */
export function hash(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: CRYPTO.HASH_SIZE });
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

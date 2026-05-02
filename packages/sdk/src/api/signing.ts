/**
 * @file signing.ts
 * Request signing utilities for API client
 */

import { CryptoUtils } from '../core/crypto';
import { ErrorCodes, GhostIDError } from '../core/errors';

/**
 * Signs a request payload with the provided private key
 * @param payload - Request payload to sign
 * @param privateKey - Private key for signing
 * @returns Base64-encoded signature
 */
export function signRequest(payload: Record<string, unknown>, privateKey: Uint8Array): string {
  // Validate inputs
  if (!payload || typeof payload !== 'object') {
    throw new GhostIDError('Invalid payload for signing', ErrorCodes.INVALID_INPUT);
  }
  if (!privateKey || !(privateKey instanceof Uint8Array) || privateKey.length === 0) {
    throw new GhostIDError('Invalid private key for signing', ErrorCodes.INVALID_INPUT);
  }

  try {
    const payloadString = JSON.stringify(payload);
    const payloadBytes = CryptoUtils.stringToBytes(payloadString);
    const signature = CryptoUtils.sign(payloadBytes, privateKey);
    return CryptoUtils.toBase64(signature);
  } catch (error) {
    throw new GhostIDError(
      'Failed to sign request payload',
      ErrorCodes.CRYPTOGRAPHY_ERROR,
      error as Error
    );
  }
}

/**
 * Verifies a request signature
 * @param payload - Request payload that was signed
 * @param signature - Base64-encoded signature
 * @param publicKey - Public key for verification
 * @returns True if signature is valid
 */
export function verifyRequest(
  payload: Record<string, unknown>,
  signature: string,
  publicKey: Uint8Array
): boolean {
  try {
    // Validate inputs
    if (!payload || typeof payload !== 'object') {
      return false;
    }
    if (!signature || typeof signature !== 'string' || signature.trim().length === 0) {
      return false;
    }
    if (!publicKey || !(publicKey instanceof Uint8Array) || publicKey.length === 0) {
      return false;
    }

    const payloadString = JSON.stringify(payload);
    const payloadBytes = CryptoUtils.stringToBytes(payloadString);
    const signatureBytes = CryptoUtils.fromBase64(signature.trim());
    return CryptoUtils.verify(signatureBytes, payloadBytes, publicKey);
  } catch {
    return false;
  }
}

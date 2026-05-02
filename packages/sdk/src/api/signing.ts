/**
 * @file signing.ts
 * Request signing utilities for API client
 */

import { ERROR_MESSAGES } from '@/constants';
import { fromBase64, sign, stringToBytes, toBase64, verify } from '../core/crypto';
import { ErrorCodes, GhostIDError } from '../core/errors';

/**
 * Signs a request payload with the provided private key
 * @param payload - Request payload to sign
 * @param privateKey - Private key for signing
 * @returns Base64-encoded signature
 */
export function signRequest(payload: Record<string, unknown>, privateKey: Uint8Array): string {
  if (!payload || typeof payload !== 'object') {
    throw new GhostIDError(ERROR_MESSAGES.INVALID_SIGNING_PAYLOAD, ErrorCodes.INVALID_INPUT);
  }
  if (privateKey.length === 0) {
    throw new GhostIDError(ERROR_MESSAGES.INVALID_SIGNING_KEY, ErrorCodes.INVALID_INPUT);
  }

  try {
    const payloadString = JSON.stringify(payload);
    const payloadBytes = stringToBytes(payloadString);
    const signature = sign(payloadBytes, privateKey);
    return toBase64(signature);
  } catch (error) {
    throw new GhostIDError(ERROR_MESSAGES.SIGNING_FAILED, ErrorCodes.CRYPTOGRAPHY_ERROR, error as Error);
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
    if (!payload || typeof payload !== 'object') {
      return false;
    }
    if (!signature || signature.trim().length === 0) {
      return false;
    }
    if (publicKey.length === 0) {
      return false;
    }

    const payloadString = JSON.stringify(payload);
    const payloadBytes = stringToBytes(payloadString);
    const signatureBytes = fromBase64(signature.trim());
    return verify(signatureBytes, payloadBytes, publicKey);
  } catch {
    return false;
  }
}

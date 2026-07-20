/**
 * Request signing utilities for API client
 */

import { canonicalJson } from '@ghostid/shared';
import { ERROR_MESSAGES } from '@/constants';
import { base64UrlToBuffer, bufferToBase64Url, stringToBytes } from '../core/crypto';
import { ErrorCodes, GhostIDError } from '../core/errors';

export async function signRequest(
  payload: Record<string, unknown>,
  privateKey: CryptoKey
): Promise<string> {
  if (!payload || typeof payload !== 'object') {
    throw new GhostIDError(ERROR_MESSAGES.INVALID_SIGNING_PAYLOAD, ErrorCodes.INVALID_INPUT);
  }
  try {
    const payloadBytes = new Uint8Array(stringToBytes(canonicalJson(payload)));
    const signatureBuffer = await crypto.subtle.sign('Ed25519', privateKey, payloadBytes);
    return bufferToBase64Url(signatureBuffer);
  } catch (error) {
    throw new GhostIDError(
      ERROR_MESSAGES.SIGNING_FAILED,
      ErrorCodes.CRYPTOGRAPHY_ERROR,
      error as Error
    );
  }
}

export async function verifyRequest(
  payload: Record<string, unknown>,
  signature: string,
  publicKey: CryptoKey
): Promise<boolean> {
  try {
    if (!payload || typeof payload !== 'object') return false;
    if (!signature || signature.trim().length === 0) return false;
    const payloadBytes = new Uint8Array(stringToBytes(canonicalJson(payload)));
    const signatureBuffer = base64UrlToBuffer(signature.trim());
    return await crypto.subtle.verify('Ed25519', publicKey, signatureBuffer, payloadBytes);
  } catch {
    return false;
  }
}

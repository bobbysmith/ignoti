/**
 * @file client.ts
 * Main API client that composes all modules
 */

import type { ApiClientOptions } from '@/types';

import { AuthApiClient } from './auth';
import { CoreApiClient } from './core';
import { DevicesApiClient } from './devices';
import { signRequest, verifyRequest } from './signing';

/**
 * Main API client for GhostID backend communication
 * Composes authentication, device management, and core functionality
 */
export class ApiClient {
  private readonly core: CoreApiClient;
  public readonly auth: AuthApiClient;
  public readonly devices: DevicesApiClient;

  constructor(options: ApiClientOptions) {
    this.core = new CoreApiClient(options);
    this.auth = new AuthApiClient(this.core.makeRequest.bind(this.core));
    this.devices = new DevicesApiClient(this.core.makeRequest.bind(this.core));
  }

  /**
   * Signs a request payload with the provided private key
   * @param payload - Request payload to sign
   * @param privateKey - Private key for signing
   * @returns Base64-encoded signature
   */
  static signRequest(payload: Record<string, unknown>, privateKey: Uint8Array): string {
    return signRequest(payload, privateKey);
  }

  /**
   * Verifies a request signature
   * @param payload - Request payload that was signed
   * @param signature - Base64-encoded signature
   * @param publicKey - Public key for verification
   * @returns True if signature is valid
   */
  static verifyRequest(
    payload: Record<string, unknown>,
    signature: string,
    publicKey: Uint8Array
  ): boolean {
    return verifyRequest(payload, signature, publicKey);
  }
}

/**
 * Creates a new API client instance
 * @param options - Client configuration options
 * @returns New API client instance
 */
export function createApiClient(options: ApiClientOptions): ApiClient {
  return new ApiClient(options);
}

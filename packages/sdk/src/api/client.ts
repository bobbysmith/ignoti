/**
 * Main API client that composes all modules
 */

import type { ApiClientOptions } from '@/types';

import { AuthApiClient } from './auth';
import { CoreApiClient } from './core';
import { DevicesApiClient } from './devices';
import { SessionsApiClient } from './sessions';
import { signRequest, verifyRequest } from './signing';

/**
 * Main API client for Ignoti backend communication
 * Composes authentication, device management, and core functionality
 */
export class ApiClient {
  private readonly core: CoreApiClient;
  public readonly auth: AuthApiClient;
  public readonly devices: DevicesApiClient;
  public readonly sessions: SessionsApiClient;

  constructor(options: ApiClientOptions) {
    this.core = new CoreApiClient(options);
    this.auth = new AuthApiClient(this.core.makeRequest.bind(this.core));
    this.devices = new DevicesApiClient(this.core.makeRequest.bind(this.core));
    this.sessions = new SessionsApiClient(this.core.makeRequest.bind(this.core));
  }

  static signRequest(payload: Record<string, unknown>, privateKey: CryptoKey): Promise<string> {
    return signRequest(payload, privateKey);
  }

  static verifyRequest(
    payload: Record<string, unknown>,
    signature: string,
    publicKey: CryptoKey
  ): Promise<boolean> {
    return verifyRequest(payload, signature, publicKey);
  }
}

export function createApiClient(options: ApiClientOptions): ApiClient {
  return new ApiClient(options);
}

/**
 * @file devices.ts
 * Device management methods for API client
 */

import {
  API_ENDPOINTS,
  HTTP_HEADERS,
  HTTP_METHODS,
  SESSION_AUTH_SCHEME,
  VALIDATION,
} from '@/constants';
import type { GetDevicesResponse } from '@/types';

import { BaseApiClient } from './base';
import { validateString } from './validation';

export class DevicesApiClient extends BaseApiClient {
  constructor(
    protected makeRequest: <T>(
      method: string,
      path: string,
      data?: Record<string, unknown> | string | number | boolean,
      headers?: Record<string, string>
    ) => Promise<T>
  ) {
    super();
  }

  async getDevices(
    sessionId: string,
    iat: number,
    signature: string,
    jti: string
  ): Promise<GetDevicesResponse> {
    const validatedSessionId = validateString(
      sessionId,
      'sessionId',
      VALIDATION.MAX_SESSION_TOKEN_LENGTH
    );
    const validatedSignature = validateString(
      signature,
      'signature',
      VALIDATION.MAX_SIGNATURE_LENGTH
    );

    return this.makeRequest<GetDevicesResponse>(
      HTTP_METHODS.GET,
      API_ENDPOINTS.DEVICES.LIST,
      undefined,
      {
        [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${validatedSessionId}`,
        [HTTP_HEADERS.SESSION_NONCE]: jti,
        [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
        [HTTP_HEADERS.SESSION_SIGNATURE]: validatedSignature,
      }
    );
  }

  async revokeDevice(deviceId: string, rootSignature: string): Promise<{ ok: boolean }> {
    const validatedDeviceId = validateString(deviceId, 'deviceId', VALIDATION.MAX_DEVICE_ID_LENGTH);
    const validatedSignature = validateString(
      rootSignature,
      'rootSignature',
      VALIDATION.MAX_SIGNATURE_LENGTH
    );

    return this.makeRequest<{ ok: boolean }>(
      HTTP_METHODS.DELETE,
      `${API_ENDPOINTS.DEVICES.REVOKE}/${validatedDeviceId}`,
      { rootSignature: validatedSignature }
    );
  }
}

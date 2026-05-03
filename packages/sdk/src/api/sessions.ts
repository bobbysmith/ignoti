/**
 * @file sessions.ts
 * Session management methods for API client
 */

import {
  API_ENDPOINTS,
  HTTP_HEADERS,
  HTTP_METHODS,
  SESSION_AUTH_SCHEME,
  VALIDATION,
} from '@/constants';
import type { GetSessionsResponse } from '@/types';

import { BaseApiClient } from './base';
import { validateString } from './validation';

export class SessionsApiClient extends BaseApiClient {
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

  async getSessions(
    sessionId: string,
    iat: number,
    signature: string
  ): Promise<GetSessionsResponse> {
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

    return this.makeRequest<GetSessionsResponse>(
      HTTP_METHODS.GET,
      API_ENDPOINTS.SESSIONS.LIST,
      undefined,
      {
        [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${validatedSessionId}`,
        [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
        [HTTP_HEADERS.SESSION_SIGNATURE]: validatedSignature,
      }
    );
  }

  async revokeSession(
    targetSessionId: string,
    currentSessionId: string,
    iat: number,
    signature: string
  ): Promise<{ ok: boolean }> {
    const validatedTargetId = validateString(
      targetSessionId,
      'targetSessionId',
      VALIDATION.MAX_SESSION_TOKEN_LENGTH
    );
    const validatedCurrentId = validateString(
      currentSessionId,
      'currentSessionId',
      VALIDATION.MAX_SESSION_TOKEN_LENGTH
    );
    const validatedSignature = validateString(
      signature,
      'signature',
      VALIDATION.MAX_SIGNATURE_LENGTH
    );

    return this.makeRequest<{ ok: boolean }>(
      HTTP_METHODS.DELETE,
      `${API_ENDPOINTS.SESSIONS.REVOKE}/${validatedTargetId}`,
      undefined,
      {
        [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${validatedCurrentId}`,
        [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
        [HTTP_HEADERS.SESSION_SIGNATURE]: validatedSignature,
      }
    );
  }
}

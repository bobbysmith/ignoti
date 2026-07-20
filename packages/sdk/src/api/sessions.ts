/**
 * Session management methods for API client
 */

import {
  API_ENDPOINTS,
  HTTP_HEADERS,
  HTTP_METHODS,
  SESSION_AUTH_SCHEME,
  VALIDATION,
} from '@/constants';
import type { MakeRequest } from './core';
import { validateString } from './validation';

interface RawSessionsResponse {
  sessions: Array<{
    id: string;
    deviceId: string;
    createdAt: string;
    lastUsedAt: string | null;
    expiresAt: string;
    isCurrent: boolean;
  }>;
}

export class SessionsApiClient {
  constructor(protected makeRequest: MakeRequest) {}

  async getSessions(
    sessionId: string,
    iat: number,
    signature: string,
    jti: string
  ): Promise<RawSessionsResponse> {
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

    return this.makeRequest<RawSessionsResponse>(
      HTTP_METHODS.GET,
      API_ENDPOINTS.SESSIONS.LIST,
      undefined,
      {
        [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${validatedSessionId}`,
        [HTTP_HEADERS.SESSION_NONCE]: jti,
        [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
        [HTTP_HEADERS.SESSION_SIGNATURE]: validatedSignature,
      }
    );
  }

  async revokeSession(
    targetSessionId: string,
    currentSessionId: string,
    iat: number,
    signature: string,
    jti: string
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
        [HTTP_HEADERS.SESSION_NONCE]: jti,
        [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
        [HTTP_HEADERS.SESSION_SIGNATURE]: validatedSignature,
      }
    );
  }

  async revokeAllSessions(
    sessionId: string,
    iat: number,
    signature: string,
    jti: string
  ): Promise<{ revoked: number }> {
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

    return this.makeRequest<{ revoked: number }>(
      HTTP_METHODS.DELETE,
      API_ENDPOINTS.SESSIONS.LIST,
      undefined,
      {
        [HTTP_HEADERS.AUTHORIZATION]: `${SESSION_AUTH_SCHEME} ${validatedSessionId}`,
        [HTTP_HEADERS.SESSION_NONCE]: jti,
        [HTTP_HEADERS.SESSION_TIMESTAMP]: String(iat),
        [HTTP_HEADERS.SESSION_SIGNATURE]: validatedSignature,
      }
    );
  }
}

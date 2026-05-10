/**
 * @file auth.ts
 * Authentication methods for API client
 */

import { API_ENDPOINTS, ERROR_MESSAGES, HTTP_METHODS, VALIDATION } from '@/constants';
import type {
  CreateSessionRequest,
  CreateSessionResponse,
  LoginRequest,
  LoginResponse,
  RecoverAccountRequest,
  RecoverAccountResponse,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  RegisterUserRequest,
  RegisterUserResponse,
  RequestChallengeResponse,
  RestoreSessionResponse,
} from '@/types';
import { ErrorCodes, GhostIDError } from '../core/errors';

import { BaseApiClient } from './base';
import { validateString } from './validation';

/**
 * Authentication methods for API client
 */
export class AuthApiClient extends BaseApiClient {
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

  /**
   * Registers a new user with their root public key
   * @param request - User registration request
   * @returns User ID and registration challenge
   */
  async registerUser(request: RegisterUserRequest): Promise<RegisterUserResponse> {
    // Validate request
    const validatedRequest = {
      ...request,
      rootPublicKey: validateString(
        request.rootPublicKey,
        'rootPublicKey',
        VALIDATION.MAX_PUBLIC_KEY_LENGTH
      ),
    };

    return this.makeRequest<RegisterUserResponse>(
      HTTP_METHODS.POST,
      API_ENDPOINTS.AUTH.REGISTER,
      validatedRequest
    );
  }

  /**
   * Registers a new device (passkey) for a user.
   * The server verifies the WebAuthn attestation and the root-key signature
   * before persisting the device.
   */
  async registerDevice(request: RegisterDeviceRequest): Promise<RegisterDeviceResponse> {
    const validated: RegisterDeviceRequest = {
      ...request,
      userId: validateString(request.userId, 'userId', VALIDATION.MAX_DEVICE_ID_LENGTH),
      rootSignature: validateString(
        request.rootSignature,
        'rootSignature',
        VALIDATION.MAX_SIGNATURE_LENGTH
      ),
    };

    if (!request.registrationResponse || typeof request.registrationResponse !== 'object') {
      throw new GhostIDError(
        ERROR_MESSAGES.INVALID_REGISTRATION_RESPONSE,
        ErrorCodes.INVALID_INPUT
      );
    }

    return this.makeRequest<RegisterDeviceResponse>(
      HTTP_METHODS.POST,
      API_ENDPOINTS.AUTH.REGISTER_DEVICE,
      validated as unknown as Record<string, unknown>
    );
  }

  /**
   * Requests a discoverable-credential authentication challenge. The server
   * returns options with an empty `allowCredentials` so the browser presents
   * all available authenticators, including password manager extensions,
   * rather than filtering to a specific credential.
   */
  async requestChallenge(): Promise<RequestChallengeResponse> {
    return this.makeRequest<RequestChallengeResponse>(
      HTTP_METHODS.POST,
      API_ENDPOINTS.AUTH.CHALLENGE,
      {}
    );
  }

  /**
   * Submits a WebAuthn assertion. The server looks up the device by
   * `assertion.id` (credential ID), verifies the assertion, and returns
   * `{ sessionChallenge, deviceId }`. No upfront `deviceId` needed.
   */
  async login(request: LoginRequest): Promise<LoginResponse> {
    if (!request.assertion || typeof request.assertion !== 'object') {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_ASSERTION_RESPONSE, ErrorCodes.INVALID_INPUT);
    }
    return this.makeRequest<LoginResponse>(HTTP_METHODS.POST, API_ENDPOINTS.AUTH.LOGIN, {
      assertion: request.assertion,
    });
  }

  /**
   * Commits a session keypair. `sessionBinding` is a compact JWS (EdDSA)
   * carrying the session public key in the `jwk` protected header and the
   * server's `sessionChallenge` as a claim. Proves the SDK holds the matching
   * private key and ties the session to a specific login event.
   */
  async createSession(request: CreateSessionRequest): Promise<CreateSessionResponse> {
    const validatedBinding = validateString(
      request.sessionBinding,
      'sessionBinding',
      VALIDATION.MAX_SESSION_BINDING_LENGTH
    );

    return this.makeRequest<CreateSessionResponse>(HTTP_METHODS.POST, API_ENDPOINTS.AUTH.SESSION, {
      sessionBinding: validatedBinding,
    });
  }

  async restoreSession(sessionBinding: string): Promise<RestoreSessionResponse> {
    const validatedBinding = validateString(
      sessionBinding,
      'sessionBinding',
      VALIDATION.MAX_SESSION_BINDING_LENGTH
    );
    return this.makeRequest<RestoreSessionResponse>(
      HTTP_METHODS.POST,
      API_ENDPOINTS.AUTH.SESSION_RESTORE,
      { sessionBinding: validatedBinding }
    );
  }

  /**
   * Looks up an existing user by their root public key (derived from the
   * mnemonic) and returns WebAuthn registration options for a new device.
   * The actual root-key proof comes in the subsequent `registerDevice` call
   * via a JWS with `purpose: 'recover-device'`.
   */
  async recoverAccount(request: RecoverAccountRequest): Promise<RecoverAccountResponse> {
    const rootPublicKey = validateString(
      request.rootPublicKey,
      'rootPublicKey',
      VALIDATION.MAX_PUBLIC_KEY_LENGTH
    );
    return this.makeRequest<RecoverAccountResponse>(HTTP_METHODS.POST, API_ENDPOINTS.AUTH.RECOVER, {
      rootPublicKey,
    });
  }
}

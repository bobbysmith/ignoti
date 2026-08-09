import { ERROR_MESSAGES } from '@/constants';
import type { FormattedCreatePasskeyResponse, FormattedGetPasskeyAssertionResponse } from '@/types';
import { bufferToBase64Url } from '../core/crypto';
import { ErrorCodes, IgnotiError } from '../core/errors';

declare const window: {
  PublicKeyCredential: typeof PublicKeyCredential;
} & typeof globalThis;

/**
 * Creates a new passkey credential for device authentication.
 * Returns a `RegistrationResponseJSON`-shaped object compatible with
 * `@simplewebauthn/server`'s `verifyRegistrationResponse`.
 */
export async function createPasskey(
  options: PublicKeyCredentialCreationOptions
): Promise<FormattedCreatePasskeyResponse> {
  if (typeof window === 'undefined' || !('credentials' in navigator)) {
    throw new IgnotiError(ERROR_MESSAGES.WEB_AUTHN_NOT_SUPPORTED, ErrorCodes.INVALID_INPUT);
  }

  let cred: PublicKeyCredential | null;

  try {
    cred = (await navigator.credentials.create({
      publicKey: options,
    })) as PublicKeyCredential | null;
  } catch (error) {
    throw new IgnotiError(
      `${ERROR_MESSAGES.PASSKEY_CREATION_FAILED}: ${(error as Error).message}`,
      ErrorCodes.CRYPTOGRAPHY_ERROR,
      error as Error
    );
  }

  if (!cred) {
    throw new IgnotiError(ERROR_MESSAGES.PASSKEY_CREATION_CANCELLED, ErrorCodes.INVALID_INPUT);
  }

  const resp = cred.response as AuthenticatorAttestationResponse;
  const transports =
    typeof resp.getTransports === 'function'
      ? (resp.getTransports() as AuthenticatorTransport[])
      : undefined;
  const authenticatorAttachment =
    (cred as PublicKeyCredential & { authenticatorAttachment?: AuthenticatorAttachment })
      .authenticatorAttachment ?? undefined;

  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type as 'public-key',
    authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64Url(resp.clientDataJSON),
      attestationObject: bufferToBase64Url(resp.attestationObject),
      transports,
    },
  };
}

/**
 * Authenticates using an existing passkey credential.
 * Returns an `AuthenticationResponseJSON`-shaped object compatible with
 * `@simplewebauthn/server`'s `verifyAuthenticationResponse`.
 */
export async function getPasskeyAssertion(
  options: PublicKeyCredentialRequestOptions
): Promise<FormattedGetPasskeyAssertionResponse> {
  if (typeof window === 'undefined' || !('credentials' in navigator)) {
    throw new IgnotiError(ERROR_MESSAGES.WEB_AUTHN_NOT_SUPPORTED, ErrorCodes.INVALID_INPUT);
  }

  let assertion: PublicKeyCredential | null;

  try {
    assertion = (await navigator.credentials.get({
      publicKey: options,
    })) as PublicKeyCredential | null;
  } catch (error) {
    throw new IgnotiError(
      `${ERROR_MESSAGES.PASSKEY_ASSERTION_FAILED}: ${(error as Error).message}`,
      ErrorCodes.CRYPTOGRAPHY_ERROR,
      error as Error
    );
  }

  if (!assertion) {
    throw new IgnotiError(ERROR_MESSAGES.PASSKEY_ASSERTION_CANCELLED, ErrorCodes.INVALID_INPUT);
  }

  const resp = assertion.response as AuthenticatorAssertionResponse;
  const authenticatorAttachment =
    (assertion as PublicKeyCredential & { authenticatorAttachment?: AuthenticatorAttachment })
      .authenticatorAttachment ?? undefined;

  return {
    id: assertion.id,
    rawId: bufferToBase64Url(assertion.rawId),
    type: assertion.type as 'public-key',
    authenticatorAttachment,
    clientExtensionResults: assertion.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64Url(resp.clientDataJSON),
      authenticatorData: bufferToBase64Url(resp.authenticatorData),
      signature: bufferToBase64Url(resp.signature),
      userHandle: resp.userHandle ? bufferToBase64Url(resp.userHandle as ArrayBuffer) : null,
    },
  };
}

export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== 'undefined' && 'credentials' in navigator && 'PublicKeyCredential' in window
  );
}

export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false;
  }
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

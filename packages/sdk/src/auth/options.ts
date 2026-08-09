import { ERROR_MESSAGES } from '@/constants';
import { base64UrlToBuffer, bufferToBase64Url } from '../core/crypto';
import { ErrorCodes, IgnotiError } from '../core/errors';

export function creationOptionsFromServer(
  optsJson: Record<string, unknown>
): PublicKeyCredentialCreationOptions {
  try {
    const j = optsJson as {
      challenge: string;
      user: { id: string; name: string; displayName: string };
      rp: PublicKeyCredentialRpEntity;
      pubKeyCredParams: PublicKeyCredentialParameters[];
      authenticatorSelection?: AuthenticatorSelectionCriteria;
      timeout?: number;
      attestation?: AttestationConveyancePreference;
      excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>;
    };
    return {
      challenge: base64UrlToBuffer(j.challenge),
      rp: j.rp,
      user: {
        id: base64UrlToBuffer(j.user.id),
        name: j.user.name,
        displayName: j.user.displayName,
      },
      pubKeyCredParams: j.pubKeyCredParams,
      authenticatorSelection: j.authenticatorSelection,
      timeout: j.timeout ?? 60000,
      attestation: j.attestation ?? 'none',
      excludeCredentials: j.excludeCredentials?.map(c => ({
        id: base64UrlToBuffer(c.id),
        type: c.type,
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
    };
  } catch {
    throw new IgnotiError(ERROR_MESSAGES.INVALID_WEBAUTHN_OPTIONS, ErrorCodes.INVALID_INPUT);
  }
}

export function extractChallenge(opts: PublicKeyCredentialCreationOptions): string {
  return bufferToBase64Url(opts.challenge as ArrayBuffer);
}

export function requestOptionsFromServer(
  optsJson: Record<string, unknown>
): PublicKeyCredentialRequestOptions {
  try {
    const j = optsJson as {
      challenge: string;
      timeout?: number;
      rpId?: string;
      userVerification?: UserVerificationRequirement;
      allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>;
    };
    return {
      challenge: base64UrlToBuffer(j.challenge),
      timeout: j.timeout ?? 60000,
      rpId: j.rpId,
      userVerification: j.userVerification ?? 'required',
      allowCredentials: j.allowCredentials?.map(c => ({
        id: base64UrlToBuffer(c.id),
        type: c.type,
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
    };
  } catch {
    throw new IgnotiError(ERROR_MESSAGES.INVALID_WEBAUTHN_OPTIONS, ErrorCodes.INVALID_INPUT);
  }
}

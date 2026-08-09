/**
 * Root-key signing as a compact JWS (RFC 7515) with EdDSA (RFC 8037).
 *
 * The SDK derives an Ed25519 root keypair from the user's mnemonic and signs
 * device-binding claims (`register-device`, `recover-device`, `revoke-device`)
 * so the server can verify the holder of the mnemonic authorized the action.
 *
 * `typ` provides cross-protocol isolation, a token minted here cannot be
 * misread as any other JWT in the application.
 */

import { ROOT_BINDING_TYP, ROOT_JWS_MAX_AGE_SECONDS, type RootPurpose } from '@ignoti/shared';
import { SignJWT } from 'jose';

export interface DeviceBindingClaims {
  purpose: RootPurpose;
  userId: string;
  credentialId: string;
  challenge: string;
}

export async function signDeviceBindingJWS(
  claims: DeviceBindingClaims,
  rootPrivateKey: CryptoKey
): Promise<string> {
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'EdDSA', typ: ROOT_BINDING_TYP })
    .setIssuedAt()
    .setExpirationTime(`${ROOT_JWS_MAX_AGE_SECONDS}s`)
    .sign(rootPrivateKey);
}

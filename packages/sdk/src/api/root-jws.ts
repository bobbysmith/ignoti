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

import { importJWK, SignJWT } from 'jose';
import { ROOT_BINDING_TYP, type RootPurpose } from '@ghostid/shared';

import { CryptoUtils } from '../core/crypto';

export interface DeviceBindingClaims {
  purpose: RootPurpose;
  userId: string;
  credentialId: string;
  /** WebAuthn challenge (base64url) binds the JWS to the same ceremony. */
  challenge: string;
}

/**
 * `rootPrivateKey` and `rootPublicKey` are both 32-byte Ed25519 (the seed
 * for the private key, `@noble`'s convention, also what JWK EdDSA expects
 * as `d`).
 */
export async function signDeviceBindingJWS(
  claims: DeviceBindingClaims,
  rootPrivateKey: Uint8Array,
  rootPublicKey: Uint8Array
): Promise<string> {
  if (rootPrivateKey.length !== 32 || rootPublicKey.length !== 32) {
    throw new Error('Ed25519 keys must be 32 bytes (seed and public key)');
  }
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: CryptoUtils.toBase64(rootPrivateKey),
    x: CryptoUtils.toBase64(rootPublicKey),
  };
  const key = await importJWK(jwk, 'EdDSA');
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'EdDSA', typ: ROOT_BINDING_TYP })
    .setIssuedAt()
    .sign(key);
}

/**
 * Session-binding JWS (RFC 7515) signed with a freshly-generated session
 * Ed25519 keypair. The public key travels in the JWS protected header as a
 * `jwk` (RFC 7517) so the server can extract it and store it as the session's
 * verification key in one step.
 *
 * Why JWS here too: the server needs to (a) prove the caller holds the session
 * private key and (b) bind the proof to the server-issued `sessionChallenge`.
 * `jose` handles header construction, signing, and verification so we don't
 * hand-roll a canonical form for signing.
 *
 * `typ` provides cross-protocol isolation (RFC 8725 §3.11) distinct from
 * `ghostid-root-binding+jwt`.
 */

import { SESSION_BINDING_TYP, SESSION_JWS_MAX_AGE_SECONDS } from '@ghostid/shared';
import { importJWK, SignJWT } from 'jose';

import { toBase64 } from '../core/crypto';

export interface SessionBindingClaims {
  /** Server-issued nonce returned from POST /login. Single-use, short-lived. */
  sessionChallenge: string;
}

/**
 * `sessionPrivateKey` and `sessionPublicKey` are both 32-byte Ed25519 (the
 * seed for the private key, `@noble`'s convention, also what JWK EdDSA
 * expects as `d`).
 */
export async function signSessionBindingJWS(
  claims: SessionBindingClaims,
  sessionPrivateKey: Uint8Array,
  sessionPublicKey: Uint8Array
): Promise<string> {
  if (sessionPrivateKey.length !== 32 || sessionPublicKey.length !== 32) {
    throw new Error('Ed25519 keys must be 32 bytes (seed and public key)');
  }
  const xB64 = toBase64(sessionPublicKey);
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: toBase64(sessionPrivateKey),
    x: xB64,
  };
  const key = await importJWK(jwk, 'EdDSA');
  return new SignJWT({ ...claims })
    .setProtectedHeader({
      alg: 'EdDSA',
      typ: SESSION_BINDING_TYP,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: xB64 },
    })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_JWS_MAX_AGE_SECONDS}s`)
    .sign(key);
}

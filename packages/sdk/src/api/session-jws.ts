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
import { SignJWT } from 'jose';

export interface SessionBindingClaims {
  /** Server-issued nonce returned from POST /login. Single-use, short-lived. */
  sessionChallenge: string;
}

/**
 * `sessionPrivateKey` is a non-extractable WebCrypto Ed25519 private key —
 * its bytes never enter the JS heap. `sessionPublicKey` is always extractable.
 */
export async function signSessionBindingJWS(
  claims: SessionBindingClaims,
  sessionPrivateKey: CryptoKey,
  sessionPublicKey: CryptoKey
): Promise<string> {
  const jwk = (await crypto.subtle.exportKey('jwk', sessionPublicKey)) as JsonWebKey;
  return new SignJWT({ ...claims })
    .setProtectedHeader({
      alg: 'EdDSA',
      typ: SESSION_BINDING_TYP,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_JWS_MAX_AGE_SECONDS}s`)
    .sign(sessionPrivateKey);
}

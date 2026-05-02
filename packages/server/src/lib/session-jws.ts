/**
 * Verifies a compact JWS (EdDSA / Ed25519) carrying a session-binding claim.
 * Mirrors `packages/sdk/src/api/session-jws.ts`.
 *
 * The session public key travels in the JWS protected header as `jwk`, so a
 * single verification step both proves the caller holds the matching private
 * key AND surfaces the public key the server should record for the session.
 *
 * Trust model: it's safe to extract the verification key from the JWS itself
 * because (a) the signature proves possession of the matching private key and
 * (b) the `sessionChallenge` claim is a server-issued, single-use, short-lived
 * nonce, so a forged JWS over a stolen challenge still requires the holder of
 * a valid Ed25519 keypair, and that keypair becomes the session's identity.
 */

import { SESSION_BINDING_TYP, SESSION_JWS_MAX_AGE_SECONDS } from '@ghostid/shared';
import { decodeProtectedHeader, EmbeddedJWK, type JWTPayload, jwtVerify } from 'jose';

interface VerifiedSessionBinding {
  /** base64url Ed25519 public key extracted from the JWS `jwk` header. */
  sessionPublicKey: string;
  payload: JWTPayload & { sessionChallenge: string };
}

/**
 * Verifies the JWS signature, header (alg/typ), and JWK shape, and returns the
 * (now trusted) `sessionPublicKey` and claim payload. The caller is responsible
 * for atomically consuming the `sessionChallenge` against the challenges table.
 */
export async function verifySessionBindingJWS(jws: string): Promise<VerifiedSessionBinding> {
  // Pull the JWK out of the protected header up front so we can return the
  // session public key alongside verification, AND validate its shape before
  // letting `jose` import it.
  const header = decodeProtectedHeader(jws);
  if (header.typ !== SESSION_BINDING_TYP) {
    throw new Error('unexpected JWS typ');
  }

  if (header.alg !== 'EdDSA') {
    throw new Error('unexpected JWS alg');
  }

  const jwk = header.jwk as { kty?: string; crv?: string; x?: string } | undefined;

  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('missing or invalid session jwk');
  }

  const xBytes = Buffer.from(jwk.x, 'base64url');
  if (xBytes.length !== 32) {
    throw new Error('session public key must be 32 bytes');
  }

  // EmbeddedJWK re-resolves the same key from the header and verifies.
  const { payload } = await jwtVerify(jws, EmbeddedJWK, {
    algorithms: ['EdDSA'],
    typ: SESSION_BINDING_TYP,
    maxTokenAge: SESSION_JWS_MAX_AGE_SECONDS,
  });

  if (typeof payload.sessionChallenge !== 'string' || payload.sessionChallenge.length === 0) {
    throw new Error('missing sessionChallenge claim');
  }

  return {
    sessionPublicKey: xBytes.toString('base64url'),
    payload: payload as JWTPayload & { sessionChallenge: string },
  };
}

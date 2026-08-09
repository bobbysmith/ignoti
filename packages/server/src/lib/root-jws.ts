import { ROOT_BINDING_TYP, ROOT_JWS_MAX_AGE_SECONDS, type RootPurpose } from '@ignoti/shared';
import { decodeJwt, importJWK, type JWTPayload, jwtVerify } from 'jose';

export interface ExpectedClaims {
  purpose: RootPurpose;
  userId: string;
  credentialId: string;
  challenge: string;
}

export { decodeJwt };

export async function verifyDeviceBindingJWS(
  jws: string,
  rootPublicKeyB64: string,
  expected: ExpectedClaims
): Promise<JWTPayload> {
  // SDK encodes with base64url (no padding). Node's 'base64url' decoder
  // tolerates either alphabet, but be explicit about what we expect.
  const pubkey = Buffer.from(rootPublicKeyB64, 'base64url');
  if (pubkey.length !== 32) {
    throw new Error('root public key must be 32 bytes');
  }

  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: pubkey.toString('base64url'),
  };
  const key = await importJWK(jwk, 'EdDSA');

  const { payload } = await jwtVerify(jws, key, {
    algorithms: ['EdDSA'],
    typ: ROOT_BINDING_TYP,
    maxTokenAge: ROOT_JWS_MAX_AGE_SECONDS,
  });

  if (
    payload.purpose !== expected.purpose ||
    payload.userId !== expected.userId ||
    payload.credentialId !== expected.credentialId ||
    payload.challenge !== expected.challenge
  ) {
    throw new Error('claim mismatch');
  }

  return payload;
}

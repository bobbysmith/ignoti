import { canonicalJson, ROOT_BINDING_TYP, SESSION_BINDING_TYP } from '@ghostid/shared';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { sql } from '../../db/client.js';

export { runMigrations } from '../../db/migrate.js';

export async function cleanDatabase(): Promise<void> {
  await sql`truncate users, devices, challenges, sessions, session_nonces restart identity cascade`;
}

export async function generateRootKeypair(): Promise<{
  privateKey: CryptoKey;
  publicKeyB64: string;
}> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA');
  const jwk = await exportJWK(publicKey);
  if (!jwk.x) {
    throw new Error('EdDSA JWK missing x coordinate');
  }
  return { privateKey, publicKeyB64: jwk.x };
}

export async function signDeviceBindingJWS(
  claims: { purpose: string; userId: string; credentialId: string; challenge: string },
  privateKey: CryptoKey
): Promise<string> {
  return new SignJWT(claims as Record<string, unknown>)
    .setProtectedHeader({ alg: 'EdDSA', typ: ROOT_BINDING_TYP })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

export async function generateSessionKeypair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  return generateKeyPair('EdDSA');
}

export async function signSessionBindingJWS(
  sessionChallenge: string,
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<string> {
  const jwk = await exportJWK(publicKey);
  return new SignJWT({ sessionChallenge })
    .setProtectedHeader({ alg: 'EdDSA', typ: SESSION_BINDING_TYP, jwk })
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(privateKey);
}

export async function buildSessionHeaders(
  method: string,
  path: string,
  sessionId: string,
  privateKey: CryptoKey
): Promise<Record<string, string>> {
  const iat = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  const payload = { htm: method.toUpperCase(), htu: path, iat, jti, sessionId };
  const bytes = new TextEncoder().encode(canonicalJson(payload));
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, bytes);
  const signature = Buffer.from(sigBuffer).toString('base64url');
  return {
    Authorization: `GhostID-Session ${sessionId}`,
    'X-GhostID-Timestamp': String(iat),
    'X-GhostID-Nonce': jti,
    'X-GhostID-Signature': signature,
  };
}

export function makeRegistrationResponse(credId: string, challenge: string) {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.create', challenge, origin: 'http://localhost:5173' })
  ).toString('base64url');
  return {
    id: credId,
    rawId: credId,
    type: 'public-key' as const,
    clientExtensionResults: {},
    response: {
      clientDataJSON,
      attestationObject: Buffer.from('{}').toString('base64url'),
      transports: ['internal'],
    },
  };
}

export function makeAssertionResponse(credId: string, challenge: string) {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: 'http://localhost:5173' })
  ).toString('base64url');
  return {
    id: credId,
    rawId: credId,
    type: 'public-key' as const,
    clientExtensionResults: {},
    response: {
      clientDataJSON,
      authenticatorData: Buffer.from('{}').toString('base64url'),
      signature: Buffer.from('sig').toString('base64url'),
      userHandle: null,
    },
  };
}

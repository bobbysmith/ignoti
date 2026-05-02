import { SESSION_BINDING_TYP } from '@ghostid/shared';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { signSessionBindingJWS } from '@/api/session-jws.ts';
import { generateSessionSigningKeypair, toBase64 } from '@/core/crypto.ts';

const VALID_CLAIMS = { sessionChallenge: 'challenge-abc' };

describe('signSessionBindingJWS', () => {
  it('produces a compact JWS with correct typ and claims', async () => {
    const { publicKey, privateKey } = generateSessionSigningKeypair();
    const jws = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);

    expect(typeof jws).toBe('string');
    expect(jws.split('.').length).toBe(3);

    const header = decodeProtectedHeader(jws);
    expect(header.alg).toBe('EdDSA');
    expect(header.typ).toBe(SESSION_BINDING_TYP);

    const payload = decodeJwt(jws);
    expect(payload.sessionChallenge).toBe(VALID_CLAIMS.sessionChallenge);
    expect(typeof payload.iat).toBe('number');
  });

  it('embeds the session public key as jwk in the protected header', async () => {
    const { publicKey, privateKey } = generateSessionSigningKeypair();
    const jws = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    const header = decodeProtectedHeader(jws);
    const jwk = header.jwk as { kty: string; crv: string; x: string };
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBe(toBase64(publicKey));
  });

  it('signature verifies against the session public key', async () => {
    const { publicKey, privateKey } = generateSessionSigningKeypair();
    const jws = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    const key = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: toBase64(publicKey) }, 'EdDSA');
    await expect(jwtVerify(jws, key, { algorithms: ['EdDSA'] })).resolves.toBeDefined();
  });

  it('produces a different JWS when iat differs', async () => {
    const { publicKey, privateKey } = generateSessionSigningKeypair();
    vi.useFakeTimers();
    const jws1 = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    vi.advanceTimersByTime(1000);
    const jws2 = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    vi.useRealTimers();
    expect(jws1).not.toBe(jws2);
  });

  it('throws when private key is not 32 bytes', async () => {
    const { publicKey } = generateSessionSigningKeypair();
    await expect(
      signSessionBindingJWS(VALID_CLAIMS, new Uint8Array(16), publicKey)
    ).rejects.toThrow('32 bytes');
  });

  it('throws when public key is not 32 bytes', async () => {
    const { privateKey } = generateSessionSigningKeypair();
    await expect(
      signSessionBindingJWS(VALID_CLAIMS, privateKey, new Uint8Array(16))
    ).rejects.toThrow('32 bytes');
  });
});

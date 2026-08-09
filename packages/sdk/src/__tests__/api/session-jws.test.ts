import { SESSION_BINDING_TYP, SESSION_JWS_MAX_AGE_SECONDS } from '@ignoti/shared';
import { decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { signSessionBindingJWS } from '@/api/session-jws.ts';
import { generateSessionSigningKeypair } from '@/core/crypto.ts';

const VALID_CLAIMS = { sessionChallenge: 'challenge-abc' };

describe('signSessionBindingJWS', () => {
  it('produces a compact JWS with correct typ and claims', async () => {
    const { publicKey, privateKey } = await generateSessionSigningKeypair();
    const jws = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);

    expect(typeof jws).toBe('string');
    expect(jws.split('.').length).toBe(3);

    const header = decodeProtectedHeader(jws);
    expect(header.alg).toBe('EdDSA');
    expect(header.typ).toBe(SESSION_BINDING_TYP);

    const payload = decodeJwt(jws);
    expect(payload.sessionChallenge).toBe(VALID_CLAIMS.sessionChallenge);
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    expect(payload.exp).toBe((payload.iat as number) + SESSION_JWS_MAX_AGE_SECONDS);
  });

  it('embeds the session public key as jwk in the protected header', async () => {
    const { publicKey, privateKey } = await generateSessionSigningKeypair();
    const jws = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    const header = decodeProtectedHeader(jws);
    const jwk = header.jwk as { kty: string; crv: string; x: string };

    const exported = (await crypto.subtle.exportKey('jwk', publicKey)) as JsonWebKey;
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBe(exported.x);
  });

  it('signature verifies against the session public key', async () => {
    const { publicKey, privateKey } = await generateSessionSigningKeypair();
    const jws = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    await expect(jwtVerify(jws, publicKey, { algorithms: ['EdDSA'] })).resolves.toBeDefined();
  });

  it('produces a different JWS when iat differs', async () => {
    const { publicKey, privateKey } = await generateSessionSigningKeypair();
    vi.useFakeTimers();
    const jws1 = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    vi.advanceTimersByTime(1000);
    const jws2 = await signSessionBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    vi.useRealTimers();
    expect(jws1).not.toBe(jws2);
  });
});

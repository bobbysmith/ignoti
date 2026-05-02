import { ROOT_BINDING_TYP, ROOT_JWS_MAX_AGE_SECONDS } from '@ghostid/shared';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { signDeviceBindingJWS } from '@/api/root-jws.ts';
import { generateSessionSigningKeypair, toBase64 } from '@/core/crypto.ts';

function makeKeypair() {
  return generateSessionSigningKeypair();
}

const VALID_CLAIMS = {
  purpose: 'register-device' as const,
  userId: 'user-123',
  credentialId: 'cred-abc',
  challenge: 'challenge-xyz',
};

describe('signDeviceBindingJWS', () => {
  it('produces a compact JWS with correct typ and claims', async () => {
    const { publicKey, privateKey } = makeKeypair();
    const jws = await signDeviceBindingJWS(VALID_CLAIMS, privateKey, publicKey);

    expect(typeof jws).toBe('string');
    expect(jws.split('.').length).toBe(3);

    const header = decodeProtectedHeader(jws);
    expect(header.alg).toBe('EdDSA');
    expect(header.typ).toBe(ROOT_BINDING_TYP);

    const payload = decodeJwt(jws);
    expect(payload.purpose).toBe(VALID_CLAIMS.purpose);
    expect(payload.userId).toBe(VALID_CLAIMS.userId);
    expect(payload.credentialId).toBe(VALID_CLAIMS.credentialId);
    expect(payload.challenge).toBe(VALID_CLAIMS.challenge);
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    expect(payload.exp).toBe((payload.iat as number) + ROOT_JWS_MAX_AGE_SECONDS);
  });

  it('signature verifies against the public key', async () => {
    const { publicKey, privateKey } = makeKeypair();
    const jws = await signDeviceBindingJWS(VALID_CLAIMS, privateKey, publicKey);

    const jwk = { kty: 'OKP', crv: 'Ed25519', x: toBase64(publicKey) };
    const key = await importJWK(jwk, 'EdDSA');
    await expect(jwtVerify(jws, key, { algorithms: ['EdDSA'] })).resolves.toBeDefined();
  });

  it('each call produces a unique JWS when iat differs', async () => {
    const { publicKey, privateKey } = makeKeypair();
    vi.useFakeTimers();
    const jws1 = await signDeviceBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    vi.advanceTimersByTime(1000);
    const jws2 = await signDeviceBindingJWS(VALID_CLAIMS, privateKey, publicKey);
    vi.useRealTimers();
    expect(jws1).not.toBe(jws2);
  });

  it('throws when private key is not 32 bytes', async () => {
    const { publicKey } = makeKeypair();
    await expect(signDeviceBindingJWS(VALID_CLAIMS, new Uint8Array(16), publicKey)).rejects.toThrow(
      '32 bytes'
    );
  });

  it('throws when public key is not 32 bytes', async () => {
    const { privateKey } = makeKeypair();
    await expect(
      signDeviceBindingJWS(VALID_CLAIMS, privateKey, new Uint8Array(16))
    ).rejects.toThrow('32 bytes');
  });

  it('signs all three RootPurpose values', async () => {
    const { publicKey, privateKey } = makeKeypair();
    for (const purpose of ['register-device', 'recover-device', 'revoke-device'] as const) {
      const jws = await signDeviceBindingJWS({ ...VALID_CLAIMS, purpose }, privateKey, publicKey);
      expect(decodeJwt(jws).purpose).toBe(purpose);
    }
  });
});

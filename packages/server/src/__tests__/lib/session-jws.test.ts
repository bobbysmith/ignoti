import { SESSION_BINDING_TYP, SESSION_JWS_MAX_AGE_SECONDS } from '@ignoti/shared';
import { exportJWK, generateKeyPair, importJWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { verifySessionBindingJWS } from '../../lib/session-jws.js';

interface KeyPairBytes {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyB64: string;
}

async function generateEd25519Bytes(): Promise<KeyPairBytes> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  const [privJwk, pubJwk] = await Promise.all([exportJWK(privateKey), exportJWK(publicKey)]);
  if (!privJwk.d || !pubJwk.x) {
    throw new Error('unexpected JWK shape from generateKeyPair');
  }
  return {
    privateKey: Buffer.from(privJwk.d, 'base64url'),
    publicKey: Buffer.from(pubJwk.x, 'base64url'),
    publicKeyB64: pubJwk.x,
  };
}

async function signSessionJWS(
  challenge: string,
  keyPair: KeyPairBytes,
  headerOverrides: Record<string, unknown> = {}
): Promise<string> {
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: Buffer.from(keyPair.privateKey).toString('base64url'),
    x: keyPair.publicKeyB64,
  };
  const key = await importJWK(jwk, 'EdDSA');
  return new SignJWT({ sessionChallenge: challenge })
    .setProtectedHeader({
      alg: 'EdDSA',
      typ: SESSION_BINDING_TYP,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: keyPair.publicKeyB64 },
      ...headerOverrides,
    })
    .setIssuedAt()
    .sign(key);
}

function tamperSignature(jws: string): string {
  const parts = jws.split('.');
  const sig = Buffer.from(parts[2], 'base64url');
  sig[0] ^= 0xff;
  parts[2] = sig.toString('base64url');
  return parts.join('.');
}

function tamperPayload(jws: string): string {
  const parts = jws.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  payload.sessionChallenge = 'tampered';
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return parts.join('.');
}

const CHALLENGE = 'server-issued-nonce-abc123';

let keypair: KeyPairBytes;

describe('verifySessionBindingJWS', () => {
  beforeAll(async () => {
    keypair = await generateEd25519Bytes();
  });

  describe('happy path', () => {
    it('returns sessionPublicKey and payload for a valid JWS', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair);
      const result = await verifySessionBindingJWS(jws);
      expect(result.sessionPublicKey).toBe(keypair.publicKeyB64);
      expect(result.payload.sessionChallenge).toBe(CHALLENGE);
    });

    it('sessionPublicKey matches the JWK x value in the header', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair);
      const result = await verifySessionBindingJWS(jws);
      expect(result.sessionPublicKey).toBe(keypair.publicKeyB64);
    });
  });

  describe('typ header validation', () => {
    it('throws when typ is wrong', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair, { typ: 'wrong-typ' });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('unexpected JWS typ');
    });

    it('throws when typ is missing', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair, { typ: undefined });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('unexpected JWS typ');
    });
  });

  describe('alg header validation', () => {
    it('throws when alg is not EdDSA', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair);
      const [header, payload, sig] = jws.split('.');
      const decoded = JSON.parse(Buffer.from(header, 'base64url').toString());
      decoded.alg = 'HS256';
      const tamperedJws = [
        Buffer.from(JSON.stringify(decoded)).toString('base64url'),
        payload,
        sig,
      ].join('.');
      await expect(verifySessionBindingJWS(tamperedJws)).rejects.toThrow('unexpected JWS alg');
    });
  });

  describe('JWK validation', () => {
    it('throws when jwk is absent from header', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair, { jwk: undefined });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('missing or invalid session jwk');
    });

    it('throws when jwk.kty is not OKP', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair, {
        jwk: { kty: 'EC', crv: 'Ed25519', x: keypair.publicKeyB64 },
      });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('missing or invalid session jwk');
    });

    it('throws when jwk.crv is not Ed25519', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair, {
        jwk: { kty: 'OKP', crv: 'X25519', x: keypair.publicKeyB64 },
      });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('missing or invalid session jwk');
    });

    it('throws when jwk.x is not a string', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair, {
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 12345 },
      });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('missing or invalid session jwk');
    });
  });

  describe('session public key length', () => {
    it('throws when jwk.x decodes to fewer than 32 bytes', async () => {
      const shortX = Buffer.alloc(16).toString('base64url');
      const jws = await signSessionJWS(CHALLENGE, keypair, {
        jwk: { kty: 'OKP', crv: 'Ed25519', x: shortX },
      });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow(
        'session public key must be 32 bytes'
      );
    });

    it('throws when jwk.x decodes to more than 32 bytes', async () => {
      const longX = Buffer.alloc(33).toString('base64url');
      const jws = await signSessionJWS(CHALLENGE, keypair, {
        jwk: { kty: 'OKP', crv: 'Ed25519', x: longX },
      });
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow(
        'session public key must be 32 bytes'
      );
    });
  });

  describe('signature verification', () => {
    it('throws when the signature segment is tampered', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair);
      await expect(verifySessionBindingJWS(tamperSignature(jws))).rejects.toThrow();
    });

    it('throws when the payload segment is tampered', async () => {
      const jws = await signSessionJWS(CHALLENGE, keypair);
      await expect(verifySessionBindingJWS(tamperPayload(jws))).rejects.toThrow();
    });
  });

  describe('expiry enforcement', () => {
    it('rejects a JWS whose exp is in the past', async () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        d: Buffer.from(keypair.privateKey).toString('base64url'),
        x: keypair.publicKeyB64,
      };
      const key = await importJWK(jwk, 'EdDSA');
      const expiredIat = Math.floor(Date.now() / 1000) - SESSION_JWS_MAX_AGE_SECONDS - 1;
      const jws = await new SignJWT({ sessionChallenge: CHALLENGE })
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: SESSION_BINDING_TYP,
          jwk: { kty: 'OKP', crv: 'Ed25519', x: keypair.publicKeyB64 },
        })
        .setIssuedAt(expiredIat)
        .setExpirationTime(expiredIat + SESSION_JWS_MAX_AGE_SECONDS)
        .sign(key);
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow();
    });
  });

  describe('sessionChallenge claim', () => {
    it('throws when sessionChallenge is absent from payload', async () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        d: Buffer.from(keypair.privateKey).toString('base64url'),
        x: keypair.publicKeyB64,
      };
      const key = await importJWK(jwk, 'EdDSA');
      const jws = await new SignJWT({})
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: SESSION_BINDING_TYP,
          jwk: { kty: 'OKP', crv: 'Ed25519', x: keypair.publicKeyB64 },
        })
        .setIssuedAt()
        .sign(key);
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('missing sessionChallenge claim');
    });

    it('throws when sessionChallenge is an empty string', async () => {
      const jws = await signSessionJWS('', keypair);
      await expect(verifySessionBindingJWS(jws)).rejects.toThrow('missing sessionChallenge claim');
    });
  });
});

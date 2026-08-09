import { ROOT_BINDING_TYP, ROOT_JWS_MAX_AGE_SECONDS } from '@ignoti/shared';
import { exportJWK, generateKeyPair, importJWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { verifyDeviceBindingJWS } from '../../lib/root-jws.js';

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

async function signRootJWS(
  claims: Record<string, unknown>,
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
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', typ: ROOT_BINDING_TYP, ...headerOverrides })
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

const VALID_CLAIMS = {
  purpose: 'register-device' as const,
  userId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  credentialId: 'test-credential-id',
  challenge: 'test-challenge-value',
};

let keypair: KeyPairBytes;
let otherKeypair: KeyPairBytes;

describe('verifyDeviceBindingJWS', () => {
  beforeAll(async () => {
    [keypair, otherKeypair] = await Promise.all([generateEd25519Bytes(), generateEd25519Bytes()]);
  });

  describe('happy path', () => {
    it('verifies a valid register-device JWS and returns the payload', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      const payload = await verifyDeviceBindingJWS(jws, keypair.publicKeyB64, VALID_CLAIMS);
      expect(payload.purpose).toBe('register-device');
      expect(payload.userId).toBe(VALID_CLAIMS.userId);
      expect(payload.credentialId).toBe(VALID_CLAIMS.credentialId);
      expect(payload.challenge).toBe(VALID_CLAIMS.challenge);
    });

    it('verifies a valid recover-device JWS', async () => {
      const claims = { ...VALID_CLAIMS, purpose: 'recover-device' as const };
      const jws = await signRootJWS(claims, keypair);
      const payload = await verifyDeviceBindingJWS(jws, keypair.publicKeyB64, claims);
      expect(payload.purpose).toBe('recover-device');
    });

    it('verifies a valid revoke-device JWS', async () => {
      const claims = { ...VALID_CLAIMS, purpose: 'revoke-device' as const };
      const jws = await signRootJWS(claims, keypair);
      const payload = await verifyDeviceBindingJWS(jws, keypair.publicKeyB64, claims);
      expect(payload.purpose).toBe('revoke-device');
    });
  });

  describe('root public key validation', () => {
    it('throws when publicKeyB64 decodes to fewer than 32 bytes', async () => {
      const shortKey = Buffer.alloc(16).toString('base64url');
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(verifyDeviceBindingJWS(jws, shortKey, VALID_CLAIMS)).rejects.toThrow(
        'root public key must be 32 bytes'
      );
    });

    it('throws when publicKeyB64 decodes to more than 32 bytes', async () => {
      const longKey = Buffer.alloc(33).toString('base64url');
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(verifyDeviceBindingJWS(jws, longKey, VALID_CLAIMS)).rejects.toThrow(
        'root public key must be 32 bytes'
      );
    });

    it('throws when publicKeyB64 is an empty string', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(verifyDeviceBindingJWS(jws, '', VALID_CLAIMS)).rejects.toThrow(
        'root public key must be 32 bytes'
      );
    });
  });

  describe('JWS structure', () => {
    it('throws when jws is not compact (missing dots)', async () => {
      await expect(
        verifyDeviceBindingJWS('notavalidjws', keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });

    it('throws when jws is an empty string', async () => {
      await expect(
        verifyDeviceBindingJWS('', keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });
  });

  describe('header validation', () => {
    it('throws when typ header is wrong', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair, { typ: 'wrong-typ' });
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });

    it('throws when alg is not EdDSA', async () => {
      // jose rejects unknown alg at verification time
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      const [header, payload, sig] = jws.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());
      decodedHeader.alg = 'RS256';
      const tamperedHeader = Buffer.from(JSON.stringify(decodedHeader)).toString('base64url');
      const tamperedJws = [tamperedHeader, payload, sig].join('.');
      await expect(
        verifyDeviceBindingJWS(tamperedJws, keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });
  });

  describe('signature verification', () => {
    it('throws when the signature segment is tampered', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(
        verifyDeviceBindingJWS(tamperSignature(jws), keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });

    it('throws when JWS is signed with a different private key', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, otherKeypair);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });
  });

  describe('token age', () => {
    it('throws when iat is missing', async () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        d: Buffer.from(keypair.privateKey).toString('base64url'),
        x: keypair.publicKeyB64,
      };
      const key = await importJWK(jwk, 'EdDSA');
      const jws = await new SignJWT(VALID_CLAIMS)
        .setProtectedHeader({ alg: 'EdDSA', typ: ROOT_BINDING_TYP })
        .sign(key);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });

    it('throws when iat is older than ROOT_JWS_MAX_AGE_SECONDS', async () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        d: Buffer.from(keypair.privateKey).toString('base64url'),
        x: keypair.publicKeyB64,
      };
      const key = await importJWK(jwk, 'EdDSA');
      const expiredIat = Math.floor(Date.now() / 1000) - ROOT_JWS_MAX_AGE_SECONDS - 1;
      const jws = await new SignJWT(VALID_CLAIMS)
        .setProtectedHeader({ alg: 'EdDSA', typ: ROOT_BINDING_TYP })
        .setIssuedAt(expiredIat)
        .sign(key);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, VALID_CLAIMS)
      ).rejects.toThrow();
    });
  });

  describe('claim validation', () => {
    it('throws on purpose mismatch', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, {
          ...VALID_CLAIMS,
          purpose: 'revoke-device',
        })
      ).rejects.toThrow('claim mismatch');
    });

    it('throws on userId mismatch', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, { ...VALID_CLAIMS, userId: 'other-user' })
      ).rejects.toThrow('claim mismatch');
    });

    it('throws on credentialId mismatch', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, {
          ...VALID_CLAIMS,
          credentialId: 'other-cred',
        })
      ).rejects.toThrow('claim mismatch');
    });

    it('throws on challenge mismatch', async () => {
      const jws = await signRootJWS(VALID_CLAIMS, keypair);
      await expect(
        verifyDeviceBindingJWS(jws, keypair.publicKeyB64, {
          ...VALID_CLAIMS,
          challenge: 'other-challenge',
        })
      ).rejects.toThrow('claim mismatch');
    });
  });
});

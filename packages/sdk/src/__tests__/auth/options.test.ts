import { describe, expect, it } from 'vitest';
import {
  creationOptionsFromServer,
  extractChallenge,
  requestOptionsFromServer,
} from '@/auth/options.ts';
import { GhostIDError } from '@/core/errors.ts';

// 'challenge' → base64url
const CHALLENGE_B64URL = 'Y2hhbGxlbmdl';
// 'user' → base64url
const USER_ID_B64URL = 'dXNlcg';
// 'cred' → base64url
const CRED_ID_B64URL = 'Y3JlZA';

function baseCreationJson(overrides: Record<string, unknown> = {}) {
  return {
    challenge: CHALLENGE_B64URL,
    user: { id: USER_ID_B64URL, name: 'alice', displayName: 'Alice' },
    rp: { name: 'Test RP' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    ...overrides,
  };
}

describe('creationOptionsFromServer', () => {
  it('decodes challenge to ArrayBuffer', () => {
    const opts = creationOptionsFromServer(baseCreationJson());
    expect(opts.challenge).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(opts.challenge as ArrayBuffer).toString()).toBe('challenge');
  });

  it('decodes user.id to ArrayBuffer', () => {
    const opts = creationOptionsFromServer(baseCreationJson());
    expect(opts.user.id).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(opts.user.id as ArrayBuffer).toString()).toBe('user');
  });

  it('passes through rp and pubKeyCredParams unchanged', () => {
    const opts = creationOptionsFromServer(baseCreationJson());
    expect(opts.rp).toEqual({ name: 'Test RP' });
    expect(opts.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }]);
  });

  it('defaults timeout to 60000 and attestation to none', () => {
    const opts = creationOptionsFromServer(baseCreationJson());
    expect(opts.timeout).toBe(60000);
    expect(opts.attestation).toBe('none');
  });

  it('maps excludeCredentials ids through base64url decode', () => {
    const opts = creationOptionsFromServer(
      baseCreationJson({
        excludeCredentials: [{ id: CRED_ID_B64URL, type: 'public-key', transports: ['usb'] }],
      })
    );
    expect(opts.excludeCredentials).toHaveLength(1);
    expect(Buffer.from(opts.excludeCredentials?.[0].id as ArrayBuffer).toString()).toBe('cred');
    expect(opts.excludeCredentials?.[0].transports).toEqual(['usb']);
  });

  it('leaves excludeCredentials undefined when absent', () => {
    const opts = creationOptionsFromServer(baseCreationJson());
    expect(opts.excludeCredentials).toBeUndefined();
  });

  it('throws GhostIDError when challenge is missing', () => {
    expect(() => creationOptionsFromServer(baseCreationJson({ challenge: undefined }))).toThrow(
      GhostIDError
    );
  });

  it('throws GhostIDError when user is missing', () => {
    expect(() => creationOptionsFromServer(baseCreationJson({ user: undefined }))).toThrow(
      GhostIDError
    );
  });
});

describe('extractChallenge', () => {
  it('round-trips the challenge back to a base64url string', () => {
    const opts = creationOptionsFromServer(baseCreationJson());
    expect(extractChallenge(opts)).toBe(CHALLENGE_B64URL);
  });
});

describe('requestOptionsFromServer', () => {
  it('decodes challenge to ArrayBuffer', () => {
    const opts = requestOptionsFromServer({ challenge: CHALLENGE_B64URL });
    expect(opts.challenge).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(opts.challenge as ArrayBuffer).toString()).toBe('challenge');
  });

  it('defaults timeout to 60000 and userVerification to required', () => {
    const opts = requestOptionsFromServer({ challenge: CHALLENGE_B64URL });
    expect(opts.timeout).toBe(60000);
    expect(opts.userVerification).toBe('required');
  });

  it('maps allowCredentials ids through base64url decode', () => {
    const opts = requestOptionsFromServer({
      challenge: CHALLENGE_B64URL,
      allowCredentials: [{ id: CRED_ID_B64URL, type: 'public-key', transports: ['internal'] }],
    });
    expect(opts.allowCredentials).toHaveLength(1);
    expect(Buffer.from(opts.allowCredentials?.[0].id as ArrayBuffer).toString()).toBe('cred');
    expect(opts.allowCredentials?.[0].transports).toEqual(['internal']);
  });

  it('leaves allowCredentials undefined when absent', () => {
    const opts = requestOptionsFromServer({ challenge: CHALLENGE_B64URL });
    expect(opts.allowCredentials).toBeUndefined();
  });

  it('throws GhostIDError when challenge is missing', () => {
    expect(() => requestOptionsFromServer({})).toThrow(GhostIDError);
  });
});

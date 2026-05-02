import { generateRegistrationOptions } from '@simplewebauthn/server';
import { describe, expect, it, vi } from 'vitest';

import { buildRegistrationOptions, extractChallenge } from '../../helpers/auth.js';

const MISSING_CHALLENGE = 'missing challenge in clientDataJSON';

vi.mock('@simplewebauthn/server');
vi.mock('../../config.js', () => ({
  config: { RP_NAME: 'GhostID', RP_ID: 'localhost' },
}));

function encodeClientDataJSON(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function makeResponse(clientDataJSON: string) {
  return { response: { clientDataJSON } };
}

describe('auth helpers', () => {
  describe('extractChallenge', () => {
    it('returns the challenge string from a valid clientDataJSON', () => {
      const challenge = 'abc123-challenge-value';
      const resp = makeResponse(encodeClientDataJSON({ type: 'webauthn.create', challenge }));
      expect(extractChallenge(resp)).toBe(challenge);
    });

    it('handles a challenge containing URL-safe base64url characters', () => {
      const challenge = 'aB3-_xYz0123456789';
      const resp = makeResponse(encodeClientDataJSON({ challenge }));
      expect(extractChallenge(resp)).toBe(challenge);
    });

    it('throws when clientDataJSON decodes to a non-JSON string', () => {
      const resp = makeResponse(Buffer.from('not json at all').toString('base64url'));
      expect(() => extractChallenge(resp)).toThrow('malformed clientDataJSON');
    });

    it('throws when clientDataJSON decodes to an empty string', () => {
      const resp = makeResponse(Buffer.from('').toString('base64url'));
      expect(() => extractChallenge(resp)).toThrow('malformed clientDataJSON');
    });

    it('throws when the challenge key is absent', () => {
      const resp = makeResponse(encodeClientDataJSON({ type: 'webauthn.create' }));
      expect(() => extractChallenge(resp)).toThrow(MISSING_CHALLENGE);
    });

    it('throws when challenge is null', () => {
      const resp = makeResponse(encodeClientDataJSON({ challenge: null }));
      expect(() => extractChallenge(resp)).toThrow(MISSING_CHALLENGE);
    });

    it('throws when challenge is a number', () => {
      const resp = makeResponse(encodeClientDataJSON({ challenge: 42 }));
      expect(() => extractChallenge(resp)).toThrow(MISSING_CHALLENGE);
    });

    it('throws when challenge is an object', () => {
      const resp = makeResponse(encodeClientDataJSON({ challenge: {} }));
      expect(() => extractChallenge(resp)).toThrow(MISSING_CHALLENGE);
    });

    it('throws when challenge is an empty string', () => {
      const resp = makeResponse(encodeClientDataJSON({ challenge: '' }));
      expect(() => extractChallenge(resp)).toThrow(MISSING_CHALLENGE);
    });
  });

  describe('buildRegistrationOptions', () => {
    const mockGenerate = vi.mocked(generateRegistrationOptions);

    it('calls generateRegistrationOptions with rpName and rpId from config', async () => {
      mockGenerate.mockResolvedValueOnce({} as never);
      await buildRegistrationOptions('test-user-id');
      expect(mockGenerate).toHaveBeenCalledWith(
        expect.objectContaining({ rpName: 'GhostID', rpID: 'localhost' })
      );
    });

    it('sets userName and encodes userId as UTF-8 bytes in userID', async () => {
      mockGenerate.mockResolvedValueOnce({} as never);
      const userId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
      await buildRegistrationOptions(userId);
      expect(mockGenerate).toHaveBeenCalledWith(
        expect.objectContaining({
          userID: new TextEncoder().encode(userId),
          userName: userId,
        })
      );
    });

    it('sets attestationType to "none"', async () => {
      mockGenerate.mockResolvedValueOnce({} as never);
      await buildRegistrationOptions('user-id');
      expect(mockGenerate).toHaveBeenCalledWith(
        expect.objectContaining({ attestationType: 'none' })
      );
    });

    it('sets residentKey to "preferred" and userVerification to "required"', async () => {
      mockGenerate.mockResolvedValueOnce({} as never);
      await buildRegistrationOptions('user-id');
      expect(mockGenerate).toHaveBeenCalledWith(
        expect.objectContaining({
          authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        })
      );
    });
  });
});

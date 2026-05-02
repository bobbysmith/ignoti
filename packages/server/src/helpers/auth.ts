import { generateRegistrationOptions } from '@simplewebauthn/server';
import { config } from '../config.js';
import { WEBAUTHN_TIMEOUT_MS } from '../constants';

interface ClientDataJSON {
  challenge: string;
}

interface WebAuthnResponse {
  response: { clientDataJSON: string };
}

export function extractChallenge(resp: WebAuthnResponse): string {
  let parsed: ClientDataJSON;
  try {
    const json = Buffer.from(resp.response.clientDataJSON, 'base64url').toString('utf-8');
    parsed = JSON.parse(json) as ClientDataJSON;
  } catch {
    throw new Error('malformed clientDataJSON');
  }
  if (typeof parsed.challenge !== 'string' || !parsed.challenge) {
    throw new Error('missing challenge in clientDataJSON');
  }
  return parsed.challenge;
}

export async function buildRegistrationOptions(userId: string) {
  return generateRegistrationOptions({
    rpName: config.RP_NAME,
    rpID: config.RP_ID,
    userName: userId,
    userID: new TextEncoder().encode(userId),
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    timeout: WEBAUTHN_TIMEOUT_MS,
  });
}

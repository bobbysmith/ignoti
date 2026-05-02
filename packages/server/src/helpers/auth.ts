import { generateRegistrationOptions } from '@simplewebauthn/server';
import { z } from 'zod';
import { config } from '../config.js';
import { WEBAUTHN_TIMEOUT_MS } from '../constants';

interface WebAuthnResponse {
  response: { clientDataJSON: string };
}

const clientDataSchema = z.object({ challenge: z.string().min(1) });

export function extractChallenge(resp: WebAuthnResponse): string {
  let parsed: unknown;
  try {
    const json = Buffer.from(resp.response.clientDataJSON, 'base64url').toString('utf-8');
    parsed = JSON.parse(json);
  } catch {
    throw new Error('malformed clientDataJSON');
  }
  const result = clientDataSchema.safeParse(parsed);
  if (!result.success) {
    throw new Error('missing challenge in clientDataJSON');
  }
  return result.data.challenge;
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

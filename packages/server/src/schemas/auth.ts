import { z } from 'zod';

import { VALIDATION } from '../constants.js';

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_CREDENTIAL_ID_LENGTH = 2048;
const MAX_TRANSPORTS = 16;

// Canonical unpadded base64url of 32 bytes: one accepted encoding per key.
const rootPublicKey = z
  .string()
  .length(VALIDATION.ROOT_PUBLIC_KEY_LENGTH)
  .regex(BASE64URL)
  .refine(v => {
    const bytes = Buffer.from(v, 'base64url');
    return bytes.length === 32 && bytes.toString('base64url') === v;
  }, 'must be a canonical base64url-encoded 32-byte key');

const credentialId = z.string().min(1).max(MAX_CREDENTIAL_ID_LENGTH).regex(BASE64URL);

export const registerBody = z.object({ rootPublicKey });

export const registerDeviceBody = z.object({
  userId: z.string().uuid(),
  registrationResponse: z
    .object({
      id: credentialId,
      rawId: credentialId,
      type: z.literal('public-key'),
      response: z.object({
        clientDataJSON: z.string(),
        attestationObject: z.string(),
        transports: z
          .array(z.string().regex(/^[a-z-]{1,32}$/))
          .max(MAX_TRANSPORTS)
          .optional(),
      }),
      authenticatorAttachment: z.string().optional(),
      clientExtensionResults: z.record(z.unknown()).optional(),
    })
    .passthrough(),
  rootSignature: z
    .string()
    .min(VALIDATION.MIN_ROOT_SIGNATURE_LENGTH)
    .max(VALIDATION.MAX_ROOT_SIGNATURE_LENGTH),
  deviceName: z
    .string()
    .max(VALIDATION.MAX_DEVICE_NAME_LENGTH)
    .regex(/^\P{Cc}*$/u, 'must not contain control characters')
    .optional(),
});

export const loginBody = z.object({
  assertion: z
    .object({
      id: credentialId,
      rawId: credentialId,
      type: z.literal('public-key'),
      response: z.object({
        clientDataJSON: z.string(),
        authenticatorData: z.string(),
        signature: z.string(),
        userHandle: z.string().nullable().optional(),
      }),
      authenticatorAttachment: z.string().optional(),
      clientExtensionResults: z.record(z.unknown()).optional(),
    })
    .passthrough(),
});

export const sessionBody = z.object({
  sessionBinding: z
    .string()
    .min(VALIDATION.MIN_SESSION_BINDING_LENGTH)
    .max(VALIDATION.MAX_SESSION_BINDING_LENGTH),
});

export const recoverBody = z.object({ rootPublicKey });

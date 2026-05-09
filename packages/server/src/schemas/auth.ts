import { z } from 'zod';

import { VALIDATION } from '../constants.js';

export const registerBody = z.object({
  rootPublicKey: z
    .string()
    .min(VALIDATION.MIN_ROOT_PUBLIC_KEY_LENGTH)
    .max(VALIDATION.MAX_ROOT_PUBLIC_KEY_LENGTH),
});

export const registerDeviceBody = z.object({
  userId: z.string().uuid(),
  registrationResponse: z
    .object({
      id: z.string(),
      rawId: z.string(),
      type: z.literal('public-key'),
      response: z.object({
        clientDataJSON: z.string(),
        attestationObject: z.string(),
        transports: z.array(z.string()).optional(),
      }),
      authenticatorAttachment: z.string().optional(),
      clientExtensionResults: z.record(z.unknown()).optional(),
    })
    .passthrough(),
  rootSignature: z
    .string()
    .min(VALIDATION.MIN_ROOT_SIGNATURE_LENGTH)
    .max(VALIDATION.MAX_ROOT_SIGNATURE_LENGTH),
  deviceName: z.string().max(VALIDATION.MAX_DEVICE_NAME_LENGTH).optional(),
});

export const loginBody = z.object({
  assertion: z
    .object({
      id: z.string(),
      rawId: z.string(),
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

export const recoverBody = z.object({
  rootPublicKey: z
    .string()
    .min(VALIDATION.MIN_ROOT_PUBLIC_KEY_LENGTH)
    .max(VALIDATION.MAX_ROOT_PUBLIC_KEY_LENGTH),
});

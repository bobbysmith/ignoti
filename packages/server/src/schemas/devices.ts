import { z } from 'zod';

import { VALIDATION } from '../constants';

export const revokeDeviceParams = z.object({
  id: z.string().uuid(),
});

export const revokeDeviceBody = z.object({
  rootSignature: z
    .string()
    .min(VALIDATION.MIN_ROOT_SIGNATURE_LENGTH)
    .max(VALIDATION.MAX_ROOT_SIGNATURE_LENGTH),
});

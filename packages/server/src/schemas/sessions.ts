import { z } from 'zod';

export const revokeSessionParams = z.object({
  id: z.string().uuid(),
});

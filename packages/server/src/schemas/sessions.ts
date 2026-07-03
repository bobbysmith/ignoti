import { z } from 'zod';

export const revokeSessionParams = z.object({
  id: z.string().uuid(),
});

// Loose length caps only: verifySessionAuth performs the real validation
// (scheme, UUID shape, timestamp window, signature) and reports granular codes.
export const verifySessionBody = z.object({
  method: z.string().min(1).max(16),
  path: z.string().min(1).max(2048),
  authorization: z.string().min(1).max(1024),
  nonce: z.string().min(1).max(256),
  timestamp: z.string().min(1).max(64),
  signature: z.string().min(1).max(1024),
});

import { z } from 'zod';

const envSchema = z.object({
  PORT: z.coerce.number().default(8787),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().url(),
  DB_PREPARE: z
    .string()
    .default('true')
    .transform(v => v.toLowerCase() !== 'false'),
  RP_ID: z.string().default('localhost'),
  RP_NAME: z.string().default('GhostID'),
  // Comma-separated list of allowed origins, e.g.
  // RP_ORIGIN=https://app.example.com,https://staging.app.example.com
  // A single value works as-is for backwards compatibility.
  RP_ORIGIN: z
    .string()
    .default('http://localhost:5173')
    .transform(v =>
      v
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
    )
    .pipe(z.array(z.string().url({ message: 'Each RP_ORIGIN entry must be a valid URL' }))),
  CHALLENGE_TTL_SECONDS: z.coerce.number().default(300),
  SESSION_TTL_SECONDS: z.coerce.number().default(60 * 60 * 24),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
});

export const config = envSchema.parse(process.env);
export type Config = typeof config;

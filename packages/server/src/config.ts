import { z } from 'zod';

const CHALLENGE_TTL_MIN_SECONDS = 30; // 30 seconds
const CHALLENGE_TTL_MAX_SECONDS = 60 * 60; // 1 hour
const CHALLENGE_TTL_DEFAULT_SECONDS = 5 * 60; // 5 minutes

const SESSION_TTL_MIN_SECONDS = 60; // 1 minute
const SESSION_TTL_MAX_SECONDS = 60 * 60 * 24 * 30; // 30 days
const SESSION_TTL_DEFAULT_SECONDS = 60 * 60 * 24; // 24 hours

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
  CHALLENGE_TTL_SECONDS: z.coerce
    .number()
    .min(CHALLENGE_TTL_MIN_SECONDS)
    .max(CHALLENGE_TTL_MAX_SECONDS)
    .default(CHALLENGE_TTL_DEFAULT_SECONDS),
  SESSION_TTL_SECONDS: z.coerce
    .number()
    .min(SESSION_TTL_MIN_SECONDS)
    .max(SESSION_TTL_MAX_SECONDS)
    .default(SESSION_TTL_DEFAULT_SECONDS),
  COOKIE_SECURE: z
    .string()
    .default('true')
    .transform(v => v.toLowerCase() !== 'false'),
  RATE_LIMIT_DISABLED: z
    .string()
    .default('false')
    .transform(v => v.toLowerCase() === 'true'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
});

const result = envSchema.safeParse(process.env);
if (!result.success) {
  const lines = result.error.issues.map(i => `  ${i.path.join('.')}: ${i.message}`);
  throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
}

export const config = result.data;

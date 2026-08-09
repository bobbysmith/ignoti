/**
 * Server-side session verification for integrator backends.
 *
 * The Ignoti SDK signs each request with an ephemeral session key
 * (`getSessionHeaders()`). This class forwards those headers to the Ignoti
 * server's introspection endpoint (POST /api/sessions/verify), which runs the
 * full check — signature, session state, timestamp window, and nonce replay —
 * and returns the authenticated identity.
 *
 * Sessions cannot be verified offline: revocation state and single-use nonces
 * live in the Ignoti server. Verify each request exactly once and never cache
 * a positive result across requests.
 */

import { IGNOTI_HEADERS, SERVER_ERROR_CODES } from '@ignoti/shared';

import { IgnotiVerifyError } from './errors.js';
import type {
  AuthReply,
  AuthRequest,
  AuthResponse,
  IgnotiVerifierOptions,
  IncomingHeaders,
  NextFunction,
  VerifyInput,
  VerifyResult,
} from './types.js';

const VERIFY_PATH = '/api/sessions/verify';
const DEFAULT_TIMEOUT_MS = 5_000;

// Incoming header names, lowercased once. Node lowercases incoming headers,
// but plucking is case-insensitive anyway for non-Node runtimes.
const HEADER_KEYS = {
  authorization: IGNOTI_HEADERS.AUTHORIZATION.toLowerCase(),
  nonce: IGNOTI_HEADERS.SESSION_NONCE.toLowerCase(),
  timestamp: IGNOTI_HEADERS.SESSION_TIMESTAMP.toLowerCase(),
  signature: IGNOTI_HEADERS.SESSION_SIGNATURE.toLowerCase(),
} as const;

function pluckHeader(headers: IncomingHeaders, wantedLower: string): string | undefined {
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === wantedLower && typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}

export class IgnotiVerifier {
  private readonly serverUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: IgnotiVerifierOptions) {
    try {
      new URL(options.serverUrl);
    } catch {
      throw new IgnotiVerifyError(`Invalid serverUrl: ${options.serverUrl}`);
    }
    this.serverUrl = options.serverUrl.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetch ?? fetch;
  }

  /**
   * Verifies the session headers of a request your backend received.
   *
   * Returns `{ valid: true, userId, ... }` or `{ valid: false, error }`.
   * Throws `IgnotiVerifyError` only when introspection itself fails
   * (Ignoti server unreachable, timeout, or unexpected response).
   */
  async verify(input: VerifyInput): Promise<VerifyResult> {
    const authorization = pluckHeader(input.headers, HEADER_KEYS.authorization);
    const nonce = pluckHeader(input.headers, HEADER_KEYS.nonce);
    const timestamp = pluckHeader(input.headers, HEADER_KEYS.timestamp);
    const signature = pluckHeader(input.headers, HEADER_KEYS.signature);

    // Fast path: unauthenticated requests skip the network round-trip.
    if (!authorization || !nonce || !timestamp || !signature) {
      return { valid: false, error: SERVER_ERROR_CODES.MISSING_SESSION_HEADERS };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.serverUrl}${VERIFY_PATH}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: input.method,
          path: input.path,
          authorization,
          nonce,
          timestamp,
          signature,
        }),
        signal: controller.signal,
      });
    } catch (err) {
      throw new IgnotiVerifyError('Ignoti session verification request failed', undefined, err);
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      throw new IgnotiVerifyError(
        `Ignoti session verification returned HTTP ${response.status}`,
        response.status
      );
    }

    try {
      return (await response.json()) as VerifyResult;
    } catch (err) {
      throw new IgnotiVerifyError(
        'Ignoti session verification returned malformed JSON',
        response.status,
        err
      );
    }
  }

  /**
   * Express-style middleware. On success, attaches the session to
   * `req.ignoti` and calls `next()`. On an invalid session, responds
   * 401 `{ error }`. On introspection failure, forwards the error to `next`.
   *
   *   app.use('/api', verifier.expressMiddleware());
   *   app.get('/api/feed', (req, res) => res.json({ userId: req.ignoti.userId }));
   */
  expressMiddleware(): (req: AuthRequest, res: AuthResponse, next: NextFunction) => void {
    return (req, res, next) => {
      this.verify({
        method: req.method,
        path: (req.originalUrl ?? req.url).split('?')[0] as string,
        headers: req.headers,
      })
        .then(result => {
          if (!result.valid) {
            res.status(401).json({ error: result.error });
            return;
          }
          const { valid: _valid, ...session } = result;
          req.ignoti = session;
          next();
        })
        .catch(next);
    };
  }

  /**
   * Fastify preHandler. On success, attaches the session to `req.ignoti`;
   * on an invalid session, replies 401 `{ error }`. Introspection failures
   * propagate to Fastify's error handler.
   *
   *   app.get('/feed', { preHandler: [verifier.fastifyPreHandler()] }, handler);
   */
  fastifyPreHandler(): (req: AuthRequest, reply: AuthReply) => Promise<void> {
    return async (req, reply) => {
      const result = await this.verify({
        method: req.method,
        path: req.url.split('?')[0] as string,
        headers: req.headers,
      });
      if (!result.valid) {
        reply.code(401).send({ error: result.error });
        return;
      }
      const { valid: _valid, ...session } = result;
      req.ignoti = session;
    };
  }
}

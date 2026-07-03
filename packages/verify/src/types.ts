import type { ServerErrorCode } from '@ghostid/shared';

// Incoming headers as any Node/edge framework exposes them.
export type IncomingHeaders = Record<string, string | string[] | undefined>;

export interface GhostIDVerifierOptions {
  // Base URL of your self-hosted GhostID server, e.g. `http://ghostid.internal:8787`.
  serverUrl: string;
  // Abort the verification request after this many milliseconds. Default: 5000.
  timeoutMs?: number;
  // Custom fetch implementation (dependency injection for tests/edge runtimes).
  fetch?: typeof fetch;
}

export interface VerifyInput {
  // HTTP method of the request your backend received.
  method: string;
  // Path of the request, exactly as the client signed it (query string is ignored).
  path: string;
  // Headers of the request your backend received.
  headers: IncomingHeaders;
}

// The authenticated identity attached to a request after verification.
export interface GhostIDSession {
  sessionId: string;
  userId: string;
  deviceId: string;
  // Epoch milliseconds.
  expiresAt: number;
}

export type VerifyResult =
  | ({ valid: true } & GhostIDSession)
  | { valid: false; error: ServerErrorCode };

// The request being authenticated. `ghostid` is set after verification succeeds.
export interface AuthRequest {
  method: string;
  url: string;
  // Express keeps the unrouted URL here; preferred over `url` when present.
  originalUrl?: string;
  headers: IncomingHeaders;
  ghostid?: GhostIDSession;
}

// Structural subset of an Express `Response`.
export interface AuthResponse {
  status(code: number): { json(body: unknown): unknown };
}

// Structural subset of a Fastify `FastifyReply`.
export interface AuthReply {
  code(statusCode: number): { send(body: unknown): unknown };
}

// Express-style continuation callback.
export type NextFunction = (err?: unknown) => void;

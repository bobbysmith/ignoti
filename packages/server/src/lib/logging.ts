import type { FastifyRequest } from 'fastify';

// Replaces Fastify's default req serializer, which logs the client IP; Ignoti keeps no IPs.
export function reqLogSerializer(req: FastifyRequest): { method: string; url: string } {
  return { method: req.method, url: req.url };
}

// Log-safe subset of an error. Other fields may hold token claims or row values.
export function errSummary(err: unknown): { name?: string; code?: string; message: string } {
  if (!(err instanceof Error)) {
    return { message: 'non-error thrown' };
  }
  const code = (err as { code?: unknown }).code;
  return {
    name: err.name,
    code: typeof code === 'string' ? code : undefined,
    message: err.message,
  };
}

// errSummary plus the stack trace, for unexpected errors.
export function errDetail(err: unknown): ReturnType<typeof errSummary> & { stack?: string } {
  return err instanceof Error ? { ...errSummary(err), stack: err.stack } : errSummary(err);
}

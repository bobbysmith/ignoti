import type { FastifyRequest } from 'fastify';

// Replaces Fastify's default req serializer, which logs the client IP; GhostID keeps no IPs.
export function reqLogSerializer(req: FastifyRequest): { method: string; url: string } {
  return { method: req.method, url: req.url };
}

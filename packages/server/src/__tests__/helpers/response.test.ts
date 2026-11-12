import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { ERROR_CODES, ERROR_MESSAGES } from '../../constants';
import { registerErrorHandler, sendError } from '../../helpers/response.js';

function makeMockReply() {
  const reply = { code: vi.fn(), send: vi.fn() };
  reply.code.mockReturnValue(reply);
  reply.send.mockReturnValue(reply);
  return reply;
}

describe('sendError', () => {
  it('calls reply.code() with the provided status', () => {
    const reply = makeMockReply();
    sendError(reply as never, 404, ERROR_CODES.USER_NOT_FOUND);
    expect(reply.code).toHaveBeenCalledWith(404);
  });

  it('calls reply.send() after reply.code()', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(reply.code).toHaveBeenCalledBefore(reply.send);
  });

  it('includes the error code in the response body', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(reply.send).toHaveBeenCalledWith(
      expect.objectContaining({ error: ERROR_CODES.INVALID_INPUT })
    );
  });

  it('looks up the human-readable message from ERROR_MESSAGES', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(reply.send).toHaveBeenCalledWith(
      expect.objectContaining({ message: ERROR_MESSAGES[ERROR_CODES.INVALID_INPUT] })
    );
  });

  it('every ERROR_CODE maps to a non-empty message string', () => {
    for (const code of Object.values(ERROR_CODES)) {
      expect(ERROR_MESSAGES[code], `missing message for code "${code}"`).toBeTruthy();
    }
  });

  it('omits the details key entirely when details is undefined', () => {
    const reply = makeMockReply();
    sendError(reply as never, 404, ERROR_CODES.USER_NOT_FOUND);
    const body = reply.send.mock.calls[0][0] as Record<string, unknown>;
    expect(Object.keys(body)).not.toContain('details');
  });

  it('includes details when an object is provided', () => {
    const reply = makeMockReply();
    const details = { field: 'rootPublicKey', issue: 'too short' };
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, details);
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ details }));
  });

  it('includes details when details is null (null !== undefined)', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, null);
    const body = reply.send.mock.calls[0][0] as Record<string, unknown>;
    expect(Object.keys(body)).toContain('details');
    expect(body.details).toBeNull();
  });

  it('includes details when details is a string', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, 'extra info');
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ details: 'extra info' }));
  });

  it('includes details when details is an array', () => {
    const reply = makeMockReply();
    const details = ['err1', 'err2'];
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, details);
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ details }));
  });

  it('returns the value of reply.send() for Fastify handler chaining', () => {
    const reply = makeMockReply();
    const result = sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(result).toBe(reply);
  });
});

describe('registerErrorHandler', () => {
  function buildApp() {
    const app = Fastify();
    registerErrorHandler(app);
    app.post('/boom', async () => {
      throw Object.assign(new Error('invalid byte sequence for encoding "UTF8": 0x00'), {
        code: '22021',
      });
    });
    app.post('/explicit-500', async () => {
      throw Object.assign(new Error('secret internal detail'), { statusCode: 500 });
    });
    app.post('/teapot', async () => {
      throw Object.assign(new Error('short and stout'), { statusCode: 418 });
    });
    app.post('/echo', async req => req.body);
    return app;
  }

  it.each(['/boom', '/explicit-500'])('answers %s with a generic 500 body', async url => {
    const res = await buildApp().inject({ method: 'POST', url });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({
      error: ERROR_CODES.INTERNAL_ERROR,
      message: ERROR_MESSAGES[ERROR_CODES.INTERNAL_ERROR],
    });
    expect(res.body).not.toContain('UTF8');
    expect(res.body).not.toContain('secret internal detail');
    expect(res.body).not.toContain('22021');
  });

  it('keeps the status and message of a 4xx error', async () => {
    const res = await buildApp().inject({ method: 'POST', url: '/teapot' });
    expect(res.statusCode).toBe(418);
    expect(res.json()).toMatchObject({ statusCode: 418, message: 'short and stout' });
  });

  it('keeps the 429 from the rate limiter', async () => {
    const app = Fastify();
    registerErrorHandler(app);
    await app.register(rateLimit, { max: 1, timeWindow: '1 minute' });
    app.get('/limited', async () => ({ ok: true }));
    await app.inject({ method: 'GET', url: '/limited' });
    const res = await app.inject({ method: 'GET', url: '/limited' });
    expect(res.statusCode).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
    expect(res.json()).toMatchObject({ statusCode: 429 });
  });

  it("keeps Fastify's own 400 for malformed JSON", async () => {
    const res = await buildApp().inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/json' },
      payload: '{not json',
    });
    expect(res.statusCode).toBe(400);
  });

  it("keeps Fastify's own 415 for an unsupported media type", async () => {
    const res = await buildApp().inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: 'a=b',
    });
    expect(res.statusCode).toBe(415);
  });
});

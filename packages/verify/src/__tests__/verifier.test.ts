import { inspect } from 'node:util';
import { SERVER_ERROR_CODES } from '@ignoti/shared';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type AuthRequest,
  IgnotiVerifier,
  IgnotiVerifyError,
  type IncomingHeaders,
} from '../index.js';

const SERVER_URL = 'http://ignoti.internal:8787';
const PUBLIC_URL = 'https://api.example.com';
const INTROSPECTION_SECRET = 'test-introspection-secret-0123456789abcdef';
const SESSION_ID = '550e8400-e29b-41d4-a716-446655440001';
const USER_ID = '550e8400-e29b-41d4-a716-446655440002';
const DEVICE_ID = '550e8400-e29b-41d4-a716-446655440003';
const EXPIRES_AT = 1719000000000;

const VALID_RESPONSE = {
  valid: true,
  sessionId: SESSION_ID,
  userId: USER_ID,
  deviceId: DEVICE_ID,
  expiresAt: EXPIRES_AT,
};

function makeHeaders(overrides: IncomingHeaders = {}): IncomingHeaders {
  return {
    authorization: `Ignoti-Session ${SESSION_ID}`,
    'x-ignoti-nonce': crypto.randomUUID(),
    'x-ignoti-timestamp': String(Math.floor(Date.now() / 1000)),
    'x-ignoti-signature': 'c2lnbmF0dXJl',
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

function makeVerifier(options: Partial<ConstructorParameters<typeof IgnotiVerifier>[0]> = {}) {
  return new IgnotiVerifier({
    serverUrl: SERVER_URL,
    publicUrl: PUBLIC_URL,
    introspectionSecret: INTROSPECTION_SECRET,
    fetch: fetchMock as unknown as typeof fetch,
    ...options,
  });
}

beforeEach(() => {
  fetchMock = vi.fn();
});

describe('IgnotiVerifier', () => {
  describe('constructor', () => {
    it('throws IgnotiVerifyError on an invalid serverUrl', () => {
      expect(() => makeVerifier({ serverUrl: 'not a url' })).toThrow(IgnotiVerifyError);
    });

    it('throws IgnotiVerifyError on an invalid publicUrl', () => {
      expect(() => makeVerifier({ publicUrl: 'not a url' })).toThrow(IgnotiVerifyError);
    });

    it.each([
      ['missing', undefined],
      ['empty', ''],
    ])('throws IgnotiVerifyError when introspectionSecret is %s', (_label, introspectionSecret) => {
      expect(() =>
        makeVerifier({ introspectionSecret: introspectionSecret as unknown as string })
      ).toThrow('introspectionSecret is required');
    });

    it.each([
      ['shorter than 32 characters', 'a'.repeat(31)],
      ['containing a space', `${'a'.repeat(32)} b`],
      ['containing a newline', `${'a'.repeat(32)}\nb`],
    ])('throws IgnotiVerifyError when introspectionSecret is %s', (_label, introspectionSecret) => {
      expect(() => makeVerifier({ introspectionSecret })).toThrow(
        'introspectionSecret must be at least 32 characters'
      );
    });

    it('never includes the rejected secret in the error message', () => {
      try {
        makeVerifier({ introspectionSecret: 'short-secret-value' });
        expect.unreachable();
      } catch (err) {
        expect((err as Error).message).not.toContain('short-secret-value');
      }
    });

    it('does not expose the secret when the verifier is logged or serialized', () => {
      const verifier = makeVerifier();
      expect(inspect(verifier, { depth: null, showHidden: true })).not.toContain(
        INTROSPECTION_SECRET
      );
      expect(JSON.stringify(verifier)).not.toContain(INTROSPECTION_SECRET);
      expect(Object.values(verifier)).not.toContain(INTROSPECTION_SECRET);
    });

    it('uses the global fetch when none is injected', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ valid: false, error: 'session_not_found' }));
      vi.stubGlobal('fetch', fetchMock);
      try {
        const verifier = makeVerifier({ fetch: undefined });
        await verifier.verify({ method: 'GET', url: '/api/feed', headers: makeHeaders() });
        expect(fetchMock).toHaveBeenCalledTimes(1);
      } finally {
        vi.unstubAllGlobals();
      }
    });

    it('sends the introspection secret as a bearer token', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ valid: false, error: 'session_not_found' }));
      await makeVerifier().verify({ method: 'GET', url: '/api/feed', headers: makeHeaders() });
      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>).Authorization).toBe(
        `Bearer ${INTROSPECTION_SECRET}`
      );
      expect(init.body as string).not.toContain(INTROSPECTION_SECRET);
    });

    it('throws IgnotiVerifyError when the server rejects the introspection secret', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ error: 'invalid_introspection_credentials' }, 401)
      );
      await expect(
        makeVerifier().verify({ method: 'GET', url: '/api/feed', headers: makeHeaders() })
      ).rejects.toMatchObject({ name: 'IgnotiVerifyError', httpStatus: 401 });
    });

    it('strips a trailing slash from serverUrl', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const verifier = makeVerifier({ serverUrl: `${SERVER_URL}/` });
      await verifier.verify({ method: 'GET', url: '/api/feed', headers: makeHeaders() });
      expect(fetchMock).toHaveBeenCalledWith(
        `${SERVER_URL}/api/sessions/verify`,
        expect.anything()
      );
    });
  });

  describe('verify', () => {
    it('passes an absolute url through unchanged', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      await makeVerifier().verify({
        method: 'GET',
        url: 'https://other.example.com/api/feed?x=1',
        headers: makeHeaders(),
      });
      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(init.body as string).url).toBe('https://other.example.com/api/feed?x=1');
    });

    it('keeps a path that looks protocol-relative on the configured publicUrl', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      await makeVerifier().verify({
        method: 'GET',
        url: '//evil.example.com/api/feed',
        headers: makeHeaders(),
      });
      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(init.body as string).url).toBe(`${PUBLIC_URL}//evil.example.com/api/feed`);
    });

    it('POSTs the forwarded material and returns the parsed result', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const headers = makeHeaders();
      const result = await makeVerifier().verify({ method: 'GET', url: '/api/feed', headers });

      expect(result).toEqual(VALID_RESPONSE);
      const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${SERVER_URL}/api/sessions/verify`);
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body as string)).toEqual({
        method: 'GET',
        url: `${PUBLIC_URL}/api/feed`,
        authorization: headers.authorization,
        nonce: headers['x-ignoti-nonce'],
        timestamp: headers['x-ignoti-timestamp'],
        signature: headers['x-ignoti-signature'],
      });
    });

    it('returns valid=false verbatim when the server rejects the session', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ valid: false, error: SERVER_ERROR_CODES.SESSION_NOT_FOUND })
      );
      const result = await makeVerifier().verify({
        method: 'GET',
        url: '/api/feed',
        headers: makeHeaders(),
      });
      expect(result).toEqual({ valid: false, error: SERVER_ERROR_CODES.SESSION_NOT_FOUND });
    });

    it.each([
      'authorization',
      'x-ignoti-nonce',
      'x-ignoti-timestamp',
      'x-ignoti-signature',
    ])('short-circuits with missing_session_headers when %s is absent, without a network call', async header => {
      const headers = makeHeaders();
      delete headers[header];
      const result = await makeVerifier().verify({ method: 'GET', url: '/x', headers });
      expect(result).toEqual({
        valid: false,
        error: SERVER_ERROR_CODES.MISSING_SESSION_HEADERS,
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('treats a multi-value (array) header as missing', async () => {
      const headers = makeHeaders({ 'x-ignoti-nonce': ['a', 'b'] });
      const result = await makeVerifier().verify({ method: 'GET', url: '/x', headers });
      expect(result).toEqual({ valid: false, error: SERVER_ERROR_CODES.MISSING_SESSION_HEADERS });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('plucks headers case-insensitively', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const result = await makeVerifier().verify({
        method: 'GET',
        url: '/api/feed',
        headers: {
          Authorization: `Ignoti-Session ${SESSION_ID}`,
          'X-Ignoti-Nonce': crypto.randomUUID(),
          'X-Ignoti-Timestamp': '1719000000',
          'X-Ignoti-Signature': 'c2ln',
        },
      });
      expect(result.valid).toBe(true);
    });

    it('throws IgnotiVerifyError with httpStatus on a non-200 response', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ error: 'invalid_input' }, 400));
      await expect(
        makeVerifier().verify({ method: 'GET', url: '/x', headers: makeHeaders() })
      ).rejects.toMatchObject({ name: 'IgnotiVerifyError', httpStatus: 400 });
    });

    it('wraps network failures in IgnotiVerifyError', async () => {
      fetchMock.mockRejectedValue(new TypeError('fetch failed'));
      await expect(
        makeVerifier().verify({ method: 'GET', url: '/x', headers: makeHeaders() })
      ).rejects.toBeInstanceOf(IgnotiVerifyError);
    });

    it('throws IgnotiVerifyError when the response body is not JSON', async () => {
      fetchMock.mockResolvedValue(new Response('not json', { status: 200 }));
      await expect(
        makeVerifier().verify({ method: 'GET', url: '/x', headers: makeHeaders() })
      ).rejects.toMatchObject({ name: 'IgnotiVerifyError' });
    });
  });

  describe('expressMiddleware', () => {
    function makeReq(overrides: Partial<AuthRequest> = {}): AuthRequest {
      return {
        method: 'GET',
        url: '/api/feed?page=2',
        originalUrl: '/api/feed?page=2',
        headers: makeHeaders(),
        ...overrides,
      };
    }

    function makeRes() {
      const json = vi.fn();
      const status = vi.fn().mockReturnValue({ json });
      return { status, json };
    }

    it('attaches req.ignoti and calls next() on a valid session', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const middleware = makeVerifier().expressMiddleware();
      const req = makeReq();
      const res = makeRes();
      const next = vi.fn();

      middleware(req, res, next);
      await vi.waitFor(() => expect(next).toHaveBeenCalledWith());

      expect(req.ignoti).toEqual({
        sessionId: SESSION_ID,
        userId: USER_ID,
        deviceId: DEVICE_ID,
        expiresAt: EXPIRES_AT,
      });
      expect(res.status).not.toHaveBeenCalled();
    });

    it('verifies the full URL, query string included, anchored to publicUrl', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const middleware = makeVerifier().expressMiddleware();
      const next = vi.fn();

      middleware(makeReq(), makeRes(), next);
      await vi.waitFor(() => expect(next).toHaveBeenCalled());

      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(init.body as string).url).toBe(`${PUBLIC_URL}/api/feed?page=2`);
    });

    it('falls back to req.url when originalUrl is absent', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ valid: false, error: 'session_not_found' }));
      const res = makeRes();
      makeVerifier().expressMiddleware()(
        makeReq({ url: '/feed?page=3', originalUrl: undefined }),
        res,
        vi.fn()
      );
      await vi.waitFor(() => expect(res.status).toHaveBeenCalledWith(401));
      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(init.body as string).url).toBe(`${PUBLIC_URL}/feed?page=3`);
    });

    it('responds 401 with the error code on an invalid session', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ valid: false, error: SERVER_ERROR_CODES.SESSION_EXPIRED })
      );
      const middleware = makeVerifier().expressMiddleware();
      const res = makeRes();
      const next = vi.fn();

      middleware(makeReq(), res, next);
      await vi.waitFor(() => expect(res.status).toHaveBeenCalledWith(401));

      expect(res.json).toHaveBeenCalledWith({ error: SERVER_ERROR_CODES.SESSION_EXPIRED });
      expect(next).not.toHaveBeenCalled();
    });

    it('forwards introspection failures to next(err)', async () => {
      fetchMock.mockRejectedValue(new TypeError('fetch failed'));
      const middleware = makeVerifier().expressMiddleware();
      const res = makeRes();
      const next = vi.fn();

      middleware(makeReq(), res, next);
      await vi.waitFor(() => expect(next).toHaveBeenCalledWith(expect.any(IgnotiVerifyError)));

      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('fastifyPreHandler', () => {
    function makeReply() {
      const send = vi.fn();
      const code = vi.fn().mockReturnValue({ send });
      return { code, send };
    }

    it('attaches req.ignoti on a valid session', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const preHandler = makeVerifier().fastifyPreHandler();
      const req = { method: 'GET', url: '/api/feed', headers: makeHeaders() };
      const reply = makeReply();

      await preHandler(req, reply);

      expect(req).toMatchObject({
        ignoti: {
          sessionId: SESSION_ID,
          userId: USER_ID,
          deviceId: DEVICE_ID,
          expiresAt: EXPIRES_AT,
        },
      });
      expect(reply.code).not.toHaveBeenCalled();
    });

    it('replies 401 with the error code on an invalid session', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ valid: false, error: SERVER_ERROR_CODES.SESSION_NONCE_USED })
      );
      const preHandler = makeVerifier().fastifyPreHandler();
      const reply = makeReply();

      const returned = await preHandler(
        { method: 'GET', url: '/api/feed', headers: makeHeaders() },
        reply
      );

      expect(reply.code).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith({ error: SERVER_ERROR_CODES.SESSION_NONCE_USED });
      expect(returned).toBe(reply);
    });

    it('propagates introspection failures', async () => {
      fetchMock.mockRejectedValue(new TypeError('fetch failed'));
      const preHandler = makeVerifier().fastifyPreHandler();

      await expect(
        preHandler({ method: 'GET', url: '/api/feed', headers: makeHeaders() }, makeReply())
      ).rejects.toBeInstanceOf(IgnotiVerifyError);
    });
  });
});

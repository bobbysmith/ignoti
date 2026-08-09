import { SERVER_ERROR_CODES } from '@ignoti/shared';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type AuthRequest,
  IgnotiVerifier,
  IgnotiVerifyError,
  type IncomingHeaders,
} from '../index.js';

const SERVER_URL = 'http://ignoti.internal:8787';
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
      expect(() => new IgnotiVerifier({ serverUrl: 'not a url' })).toThrow(IgnotiVerifyError);
    });

    it('strips a trailing slash from serverUrl', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const verifier = makeVerifier({ serverUrl: `${SERVER_URL}/` });
      await verifier.verify({ method: 'GET', path: '/api/feed', headers: makeHeaders() });
      expect(fetchMock).toHaveBeenCalledWith(
        `${SERVER_URL}/api/sessions/verify`,
        expect.anything()
      );
    });
  });

  describe('verify', () => {
    it('POSTs the forwarded material and returns the parsed result', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const headers = makeHeaders();
      const result = await makeVerifier().verify({ method: 'GET', path: '/api/feed', headers });

      expect(result).toEqual(VALID_RESPONSE);
      const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${SERVER_URL}/api/sessions/verify`);
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body as string)).toEqual({
        method: 'GET',
        path: '/api/feed',
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
        path: '/api/feed',
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
      const result = await makeVerifier().verify({ method: 'GET', path: '/x', headers });
      expect(result).toEqual({
        valid: false,
        error: SERVER_ERROR_CODES.MISSING_SESSION_HEADERS,
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('treats a multi-value (array) header as missing', async () => {
      const headers = makeHeaders({ 'x-ignoti-nonce': ['a', 'b'] });
      const result = await makeVerifier().verify({ method: 'GET', path: '/x', headers });
      expect(result).toEqual({ valid: false, error: SERVER_ERROR_CODES.MISSING_SESSION_HEADERS });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('plucks headers case-insensitively', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const result = await makeVerifier().verify({
        method: 'GET',
        path: '/api/feed',
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
        makeVerifier().verify({ method: 'GET', path: '/x', headers: makeHeaders() })
      ).rejects.toMatchObject({ name: 'IgnotiVerifyError', httpStatus: 400 });
    });

    it('wraps network failures in IgnotiVerifyError', async () => {
      fetchMock.mockRejectedValue(new TypeError('fetch failed'));
      await expect(
        makeVerifier().verify({ method: 'GET', path: '/x', headers: makeHeaders() })
      ).rejects.toBeInstanceOf(IgnotiVerifyError);
    });

    it('throws IgnotiVerifyError when the response body is not JSON', async () => {
      fetchMock.mockResolvedValue(new Response('not json', { status: 200 }));
      await expect(
        makeVerifier().verify({ method: 'GET', path: '/x', headers: makeHeaders() })
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

    it('strips the query string from the verified path', async () => {
      fetchMock.mockResolvedValue(jsonResponse(VALID_RESPONSE));
      const middleware = makeVerifier().expressMiddleware();
      const next = vi.fn();

      middleware(makeReq(), makeRes(), next);
      await vi.waitFor(() => expect(next).toHaveBeenCalled());

      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(init.body as string).path).toBe('/api/feed');
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

      await preHandler({ method: 'GET', url: '/api/feed', headers: makeHeaders() }, reply);

      expect(reply.code).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith({ error: SERVER_ERROR_CODES.SESSION_NONCE_USED });
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

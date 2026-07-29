import { afterEach, describe, expect, it, vi } from 'vitest';

import { CoreApiClient } from '@/api/core.ts';
import { ErrorCodes, GhostIDError } from '@/core/errors.ts';

const BASE_URL = 'http://localhost:3000';
const API_TEST_PATH = '/api/test';

function makeClient(overrides?: { baseUrl?: string; timeout?: number; retryAttempts?: number }) {
  return new CoreApiClient({ baseUrl: BASE_URL, retryAttempts: 1, ...overrides });
}

function mockFetch(status: number, body: unknown, contentType = 'application/json') {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    headers: { get: () => contentType },
    json: () => Promise.resolve(body),
  });
}

describe('code api', () => {
  describe('CoreApiClient constructor', () => {
    afterEach(() => vi.unstubAllGlobals());
    it('accepts http://localhost', () => {
      expect(() => makeClient()).not.toThrow();
    });

    it('accepts http://127.0.0.1', () => {
      expect(() => makeClient({ baseUrl: 'http://127.0.0.1:3000' })).not.toThrow();
    });

    it('accepts https', () => {
      expect(() => makeClient({ baseUrl: 'https://api.example.com' })).not.toThrow();
    });

    it('rejects plain http on non-localhost', () => {
      expect(() => makeClient({ baseUrl: 'http://api.example.com' })).toThrow(GhostIDError);
    });

    it('rejects missing baseUrl', () => {
      expect(() => makeClient({ baseUrl: '' })).toThrow(GhostIDError);
    });

    it('rejects invalid URL format', () => {
      expect(() => makeClient({ baseUrl: 'not-a-url' })).toThrow(GhostIDError);
    });

    it('rejects timeout <= 0', () => {
      expect(() => makeClient({ timeout: 0 })).toThrow(GhostIDError);
      expect(() => makeClient({ timeout: -1 })).toThrow(GhostIDError);
    });

    it('rejects timeout > 300000', () => {
      expect(() => makeClient({ timeout: 300_001 })).toThrow(GhostIDError);
    });

    it('rejects retryAttempts < 1', () => {
      expect(() => makeClient({ retryAttempts: 0 })).toThrow(GhostIDError);
    });

    it('rejects retryAttempts > 10', () => {
      expect(() => makeClient({ retryAttempts: 11 })).toThrow(GhostIDError);
    });

    it('strips trailing slash from baseUrl', async () => {
      const client = makeClient({ baseUrl: BASE_URL });
      const fetch = mockFetch(200, { ok: true });
      vi.stubGlobal('fetch', fetch);
      await client.makeRequest('GET', '/test');
      expect(fetch.mock.calls[0][0]).toBe(`${BASE_URL}/test`);
    });
  });

  describe('CoreApiClient.makeRequest', () => {
    it('returns parsed JSON on 200', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, { userId: 'abc' }));
      const result = await client.makeRequest('GET', API_TEST_PATH);
      expect(result).toEqual({ userId: 'abc' });
    });

    it('throws GhostIDError on 4xx without retry', async () => {
      const client = makeClient({ retryAttempts: 3 });
      const fetch = mockFetch(400, { error: 'invalid_input', message: 'bad' });
      vi.stubGlobal('fetch', fetch);
      await expect(client.makeRequest('POST', API_TEST_PATH, {})).rejects.toThrow(GhostIDError);
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('maps a challenge error to INVALID_CHALLENGE', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(400, { error: 'invalid_or_expired_challenge' }));
      const err = (await client
        .makeRequest('POST', API_TEST_PATH, {})
        .catch(e => e)) as GhostIDError;
      expect(err.code).toBe(ErrorCodes.INVALID_CHALLENGE);
      expect(err.httpStatus).toBe(400);
    });

    it('maps a signature error to INVALID_SIGNATURE', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(401, { error: 'invalid_root_signature' }));
      const err = (await client
        .makeRequest('DELETE', '/api/devices/abc', {})
        .catch(e => e)) as GhostIDError;
      expect(err.code).toBe(ErrorCodes.INVALID_SIGNATURE);
    });

    it('leaves an unmapped server error as API_ERROR', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(400, { error: 'invalid_input' }));
      const err = (await client
        .makeRequest('POST', API_TEST_PATH, {})
        .catch(e => e)) as GhostIDError;
      expect(err.code).toBe(ErrorCodes.API_ERROR);
    });

    it('throws GhostIDError on 5xx and retries', async () => {
      const client = makeClient({ retryAttempts: 3 });
      const fetch = mockFetch(500, { error: 'server_error', message: 'oops' });
      vi.stubGlobal('fetch', fetch);
      await expect(client.makeRequest('POST', API_TEST_PATH, {})).rejects.toThrow(GhostIDError);
      expect(fetch).toHaveBeenCalledTimes(3);
    });

    it('retries a TypeError network failure and succeeds on a later attempt', async () => {
      vi.useFakeTimers();
      const client = makeClient({ retryAttempts: 3 });
      const fetchMock = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: '200',
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({ userId: 'abc' }),
        });
      vi.stubGlobal('fetch', fetchMock);

      const assertion = client.makeRequest('GET', API_TEST_PATH);
      await vi.runAllTimersAsync();
      await expect(assertion).resolves.toEqual({ userId: 'abc' });
      expect(fetchMock).toHaveBeenCalledTimes(2);
      vi.useRealTimers();
    });

    it('exhausts attempts when a TypeError network failure persists', async () => {
      vi.useFakeTimers();
      const client = makeClient({ retryAttempts: 3 });
      const fetchMock = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
      vi.stubGlobal('fetch', fetchMock);

      const assertion = expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow(
        GhostIDError
      );
      await vi.runAllTimersAsync();
      await assertion;
      expect(fetchMock).toHaveBeenCalledTimes(3);
      vi.useRealTimers();
    });

    it('retries on non-TypeError fetch error and exhausts attempts', async () => {
      vi.useFakeTimers();
      const client = makeClient({ retryAttempts: 3 });
      const fetchMock = vi.fn().mockRejectedValue(new Error('connection reset'));
      vi.stubGlobal('fetch', fetchMock);

      const assertion = expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow(
        'connection reset'
      );
      await vi.runAllTimersAsync();
      await assertion;
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('throws GhostIDError on timeout (AbortError)', async () => {
      const client = makeClient({ timeout: 100 });
      vi.stubGlobal(
        'fetch',
        vi.fn().mockRejectedValue(Object.assign(new Error('aborted'), { name: 'AbortError' }))
      );
      await expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow('timed out');
    });

    it('wraps non-Error fetch rejections', async () => {
      const client = makeClient({ retryAttempts: 1 });
      vi.stubGlobal('fetch', vi.fn().mockRejectedValue('network down'));
      await expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow(GhostIDError);
    });

    it('throws on invalid path', async () => {
      const client = makeClient();
      await expect(client.makeRequest('GET', '')).rejects.toThrow(GhostIDError);
      await expect(client.makeRequest('GET', 'no-leading-slash')).rejects.toThrow(GhostIDError);
    });

    it('throws on invalid HTTP method', async () => {
      const client = makeClient();
      await expect(client.makeRequest('CONNECT', API_TEST_PATH)).rejects.toThrow(GhostIDError);
    });

    it('throws on forbidden header', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, {}));
      await expect(
        client.makeRequest('GET', API_TEST_PATH, undefined, { host: 'evil.com' })
      ).rejects.toThrow(GhostIDError);
    });

    it('throws on header with CR/LF (injection guard)', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, {}));
      await expect(
        client.makeRequest('GET', API_TEST_PATH, undefined, {
          'x-custom': 'val\r\nInjected: header',
        })
      ).rejects.toThrow(GhostIDError);
    });

    it('throws when request body exceeds size limit', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, {}));
      const bigPayload = { data: 'x'.repeat(1024 * 1024 + 1) };
      await expect(client.makeRequest('POST', API_TEST_PATH, bigPayload)).rejects.toThrow(
        GhostIDError
      );
    });

    it('throws GhostIDError when response JSON is unparseable', async () => {
      const client = makeClient();
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          headers: { get: () => 'application/json' },
          json: () => Promise.reject(new Error('bad json')),
        })
      );
      await expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow(GhostIDError);
    });

    it('throws when path exceeds MAX_PATH_LENGTH', async () => {
      const client = makeClient();
      const longPath = `/${'a'.repeat(2049)}`;
      await expect(client.makeRequest('GET', longPath)).rejects.toThrow('Path too long');
    });

    it('throws on invalid header name (non-token characters)', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, {}));
      await expect(
        client.makeRequest('GET', API_TEST_PATH, undefined, { 'bad header': 'value' })
      ).rejects.toThrow(GhostIDError);
    });

    it('throws on header value exceeding max length', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, {}));
      await expect(
        client.makeRequest('GET', API_TEST_PATH, undefined, { 'x-custom': 'x'.repeat(4097) })
      ).rejects.toThrow(GhostIDError);
    });

    it('throws on circular reference in body (safeStringify catch)', async () => {
      const client = makeClient();
      vi.stubGlobal('fetch', mockFetch(200, {}));
      const circular: Record<string, unknown> = {};
      circular.self = circular;
      await expect(client.makeRequest('POST', API_TEST_PATH, circular)).rejects.toThrow(
        GhostIDError
      );
    });

    it('does not attach body for GET requests', async () => {
      const client = makeClient();
      const fetch = mockFetch(200, {});
      vi.stubGlobal('fetch', fetch);
      await client.makeRequest('GET', API_TEST_PATH, { data: 'ignored' });
      expect(fetch.mock.calls[0][1].body).toBeUndefined();
    });

    it('does not send Content-Type on bodyless DELETE', async () => {
      const client = makeClient();
      const fetch = mockFetch(200, {});
      vi.stubGlobal('fetch', fetch);
      await client.makeRequest('DELETE', API_TEST_PATH);
      const headers = fetch.mock.calls[0][1].headers as Record<string, string>;
      expect(headers['content-type']).toBeUndefined();
      expect(fetch.mock.calls[0][1].body).toBeUndefined();
    });

    it('sends Content-Type on DELETE with body', async () => {
      const client = makeClient();
      const fetch = mockFetch(200, {});
      vi.stubGlobal('fetch', fetch);
      await client.makeRequest('DELETE', API_TEST_PATH, { id: '123' });
      const headers = fetch.mock.calls[0][1].headers as Record<string, string>;
      expect(headers['Content-Type']).toBe('application/json');
      expect(fetch.mock.calls[0][1].body).toBe('{"id":"123"}');
    });

    it('uses statusText as error message when response is not JSON', async () => {
      const client = makeClient();
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          headers: { get: () => 'text/plain' },
          json: () => Promise.reject(new Error('not json')),
        })
      );
      const err = (await client.makeRequest('GET', API_TEST_PATH).catch(e => e)) as GhostIDError;
      expect(err).toBeInstanceOf(GhostIDError);
      expect(err.message).toContain('Service Unavailable');
    });

    it('uses HTTP status line when error response JSON has no error or message field', async () => {
      const client = makeClient();
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: false,
          status: 422,
          statusText: 'Unprocessable Entity',
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({}),
        })
      );
      const err = (await client.makeRequest('GET', API_TEST_PATH).catch(e => e)) as GhostIDError;
      expect(err).toBeInstanceOf(GhostIDError);
      expect(err.message).toContain('HTTP 422');
    });

    it('falls through to statusText when content-type is JSON but body fails to parse (parseErrorResponse catch)', async () => {
      const client = makeClient();
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          headers: { get: () => 'application/json' },
          json: () => Promise.reject(new Error('malformed')),
        })
      );
      const err = (await client.makeRequest('GET', API_TEST_PATH).catch(e => e)) as GhostIDError;
      expect(err).toBeInstanceOf(GhostIDError);
      expect(err.message).toContain('Internal Server Error');
    });

    it('truncates error messages longer than 500 characters', async () => {
      const client = makeClient();
      const longMessage = 'x'.repeat(501);
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({ error: longMessage }),
        })
      );
      const err = (await client.makeRequest('GET', API_TEST_PATH).catch(e => e)) as GhostIDError;
      expect(err.message).toMatch(/^x{500}\.\.\.$/);
    });

    it('forwards valid custom headers to fetch', async () => {
      const client = makeClient();
      const fetch = mockFetch(200, {});
      vi.stubGlobal('fetch', fetch);
      await client.makeRequest('GET', API_TEST_PATH, undefined, { 'x-request-id': 'abc123' });
      const sentHeaders = fetch.mock.calls[0][1].headers as Record<string, string>;
      expect(sentHeaders['x-request-id']).toBe('abc123');
    });
  });

  describe('onUnauthorized interceptor', () => {
    afterEach(() => vi.unstubAllGlobals());

    function makeClientWithInterceptor(
      onUnauthorized: (method: string, path: string) => Promise<Record<string, string>>
    ) {
      return new CoreApiClient({ baseUrl: BASE_URL, retryAttempts: 1, onUnauthorized });
    }

    it('calls onUnauthorized on 401, retries with fresh headers, and returns result', async () => {
      const freshHeaders = { Authorization: 'GhostID-Session new-sess' };
      const onUnauthorized = vi.fn().mockResolvedValue(freshHeaders);
      const client = makeClientWithInterceptor(onUnauthorized);

      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({ error: 'unauthorized' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({ data: 'ok' }),
        });
      vi.stubGlobal('fetch', fetchMock);

      const result = await client.makeRequest('GET', '/api/devices');
      expect(onUnauthorized).toHaveBeenCalledWith('GET', '/api/devices');
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ data: 'ok' });

      const retryHeaders = fetchMock.mock.calls[1][1].headers as Record<string, string>;
      expect(retryHeaders.authorization).toBe('GhostID-Session new-sess');
    });

    it('throws CLOCK_SKEW without invoking the interceptor on a timestamp-range 401', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({});
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'session_timestamp_out_of_range' }));

      const err = (await client.makeRequest('GET', '/api/devices').catch(e => e)) as GhostIDError;
      expect(err.code).toBe('CLOCK_SKEW');
      expect(onUnauthorized).not.toHaveBeenCalled();
    });

    it('throws on 401 without retrying when onUnauthorized is not configured', async () => {
      const client = makeClient({ retryAttempts: 1 });
      const fetchMock = mockFetch(401, { error: 'unauthorized' });
      vi.stubGlobal('fetch', fetchMock);

      await expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow(GhostIDError);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('does not intercept 401 on the login path', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({});
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'unauthorized' }));

      await expect(client.makeRequest('POST', '/api/auth/login', {})).rejects.toThrow(GhostIDError);
      expect(onUnauthorized).not.toHaveBeenCalled();
    });

    it('does not intercept 401 on the session restore path', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({});
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'unauthorized' }));

      await expect(client.makeRequest('POST', '/api/auth/session/restore', {})).rejects.toThrow(
        GhostIDError
      );
      expect(onUnauthorized).not.toHaveBeenCalled();
    });

    it('does not intercept 401 on device registration (root-signature failure is terminal)', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({});
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'invalid_root_signature' }));

      const err = (await client
        .makeRequest('POST', '/api/auth/register/device', {})
        .catch(e => e)) as GhostIDError;
      expect(err.message).toBe('invalid_root_signature');
      expect(onUnauthorized).not.toHaveBeenCalled();
    });

    it('does not intercept 401 on device revocation (authorized by root JWS, not session)', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({});
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'invalid_root_signature' }));

      await expect(
        client.makeRequest('DELETE', '/api/devices/00000000-0000-0000-0000-000000000000', {})
      ).rejects.toThrow(GhostIDError);
      expect(onUnauthorized).not.toHaveBeenCalled();
    });

    it('intercepts 401 on session revocation by id', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({ Authorization: 'GhostID-Session new' });
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'unauthorized' }));

      await expect(
        client.makeRequest('DELETE', '/api/sessions/00000000-0000-0000-0000-000000000000')
      ).rejects.toThrow(GhostIDError);
      expect(onUnauthorized).toHaveBeenCalledTimes(1);
    });

    it('propagates onUnauthorized error when the callback throws', async () => {
      const onUnauthorized = vi.fn().mockRejectedValue(new Error('restore failed'));
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'unauthorized' }));

      await expect(client.makeRequest('GET', '/api/devices')).rejects.toThrow('restore failed');
    });

    it('does not retry a second time if the retried request also returns 401', async () => {
      const onUnauthorized = vi.fn().mockResolvedValue({ Authorization: 'GhostID-Session new' });
      const client = makeClientWithInterceptor(onUnauthorized);
      vi.stubGlobal('fetch', mockFetch(401, { error: 'unauthorized' }));

      await expect(client.makeRequest('GET', '/api/devices')).rejects.toThrow(GhostIDError);
      expect(onUnauthorized).toHaveBeenCalledTimes(1);
      expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(2);
    });
  });
});

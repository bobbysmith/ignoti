import { afterEach, describe, expect, it, vi } from 'vitest';

import { CoreApiClient } from '@/api/core.ts';
import { GhostIDError } from '@/core/errors.ts';

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

    it('throws GhostIDError on 5xx and retries', async () => {
      const client = makeClient({ retryAttempts: 3 });
      const fetch = mockFetch(500, { error: 'server_error', message: 'oops' });
      vi.stubGlobal('fetch', fetch);
      await expect(client.makeRequest('POST', API_TEST_PATH, {})).rejects.toThrow(GhostIDError);
      expect(fetch).toHaveBeenCalledTimes(3);
    });

    it('rethrows TypeError immediately on network-level failure', async () => {
      const client = makeClient();
      const networkError = new TypeError('Failed to fetch');
      vi.stubGlobal('fetch', vi.fn().mockRejectedValue(networkError));
      await expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow(networkError);
    });

    it('throws GhostIDError on timeout (AbortError)', async () => {
      const client = makeClient({ timeout: 100 });
      vi.stubGlobal(
        'fetch',
        vi.fn().mockRejectedValue(Object.assign(new Error('aborted'), { name: 'AbortError' }))
      );
      await expect(client.makeRequest('GET', API_TEST_PATH)).rejects.toThrow('timed out');
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
});

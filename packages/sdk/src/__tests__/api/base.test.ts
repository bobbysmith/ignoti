import { describe, expect, it, vi } from 'vitest';
import { BaseApiClient } from '@/api/base.ts';

class ConcreteClient extends BaseApiClient {
  makeRequest = vi.fn();
}

describe('BaseApiClient', () => {
  it('can be subclassed and makeRequest called', async () => {
    const client = new ConcreteClient();
    client.makeRequest.mockResolvedValueOnce({ ok: true });
    const result = await client.makeRequest('GET', '/test');
    expect(result).toEqual({ ok: true });
    expect(client.makeRequest).toHaveBeenCalledWith('GET', '/test');
  });
});

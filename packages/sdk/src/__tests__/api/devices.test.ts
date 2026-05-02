import { describe, expect, it, vi } from 'vitest';
import { DevicesApiClient } from '@/api/devices.ts';
import { VALIDATION } from '@/constants/index.ts';

function makeClient() {
  const makeRequest = vi.fn();
  return { client: new DevicesApiClient(makeRequest), makeRequest };
}

const SESSION_ID = 'session-uuid-1234';
const IAT = 1700000000;
const SIGNATURE = 'sig-abc';
const DEVICE_ID = 'device-uuid-5678';

describe('DevicesApiClient', () => {
  describe('getDevices', () => {
    it('calls makeRequest with session headers', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ devices: [] });
      await client.getDevices(SESSION_ID, IAT, SIGNATURE);
      expect(makeRequest).toHaveBeenCalledWith(
        'GET',
        '/api/devices',
        undefined,
        expect.objectContaining({
          Authorization: expect.stringContaining(SESSION_ID),
          'X-GhostID-Timestamp': String(IAT),
          'X-GhostID-Signature': SIGNATURE,
        })
      );
    });

    it('throws when sessionId is empty', async () => {
      const { client } = makeClient();
      await expect(client.getDevices('', IAT, SIGNATURE)).rejects.toThrow();
    });

    it('throws when signature is empty', async () => {
      const { client } = makeClient();
      await expect(client.getDevices(SESSION_ID, IAT, '')).rejects.toThrow();
    });

    it('throws when sessionId exceeds MAX_SESSION_TOKEN_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SESSION_TOKEN_LENGTH + 1);
      await expect(client.getDevices(long, IAT, SIGNATURE)).rejects.toThrow(
        'exceeds maximum length'
      );
    });
  });

  describe('revokeDevice', () => {
    it('calls makeRequest with deviceId in path and rootSignature in body', async () => {
      const { client, makeRequest } = makeClient();
      makeRequest.mockResolvedValue({ ok: true });
      await client.revokeDevice(DEVICE_ID, 'root-sig');
      expect(makeRequest).toHaveBeenCalledWith('DELETE', expect.stringContaining(DEVICE_ID), {
        rootSignature: 'root-sig',
      });
    });

    it('throws when deviceId is empty', async () => {
      const { client } = makeClient();
      await expect(client.revokeDevice('', 'sig')).rejects.toThrow();
    });

    it('throws when rootSignature is empty', async () => {
      const { client } = makeClient();
      await expect(client.revokeDevice(DEVICE_ID, '')).rejects.toThrow();
    });

    it('throws when rootSignature exceeds MAX_SIGNATURE_LENGTH', async () => {
      const { client } = makeClient();
      const long = 'a'.repeat(VALIDATION.MAX_SIGNATURE_LENGTH + 1);
      await expect(client.revokeDevice(DEVICE_ID, long)).rejects.toThrow('exceeds maximum length');
    });
  });
});

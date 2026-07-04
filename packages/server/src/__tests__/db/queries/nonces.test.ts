import { beforeEach, describe, expect, it, vi } from 'vitest';

import { sql } from '../../../db/client.js';
import { storeNonce } from '../../../db/queries/nonces.js';

vi.mock('../../../db/client.js', () => ({ sql: vi.fn() }));

const JTI = '9f1b6b2e-7c1d-4c62-9e6a-0d3f5a8b4c21';
const EXPIRES_AT = new Date('2026-07-04T00:01:00Z');

describe('nonces db queries', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('storeNonce', () => {
    it('returns true when the insert stores a new jti', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ jti: JTI }] as never);
      await expect(storeNonce(JTI, EXPIRES_AT)).resolves.toBe(true);
    });

    it('returns false when the jti already exists (conflict, no row returned)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(storeNonce(JTI, EXPIRES_AT)).resolves.toBe(false);
    });

    it('executes INSERT with the provided jti and expiry', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ jti: JTI }] as never);
      await storeNonce(JTI, EXPIRES_AT);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([JTI, EXPIRES_AT]));
    });
  });
});

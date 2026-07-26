import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CHALLENGE_PURPOSE } from '../../../constants';
import { sql } from '../../../db/client.js';
import {
  consumeLoginChallenge,
  consumeRecoverChallenge,
  consumeRegisterChallenge,
  consumeSessionChallenge,
  insertLoginChallenge,
  insertRecoverChallenge,
  insertRegisterChallenge,
  insertSessionChallenge,
} from '../../../db/queries/challenges.js';

vi.mock('../../../db/client.js', () => ({ sql: vi.fn() }));

const CHALLENGE_VALUE = 'test-challenge-value';
const USER_ID = 'user-uuid-1234';
const DEVICE_ID = 'device-uuid-5678';
const EXPIRES_AT = new Date('2026-01-01T00:00:00Z');

describe('challenges db queries', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('insertRegisterChallenge', () => {
    it('executes INSERT with correct value, purpose=register, userId, and expiresAt', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await insertRegisterChallenge(CHALLENGE_VALUE, USER_ID, EXPIRES_AT);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args[1]).toBe(CHALLENGE_VALUE);
      expect(args[2]).toBe(CHALLENGE_PURPOSE.REGISTER);
      expect(args[3]).toBe(USER_ID);
      expect(args[4]).toBe(EXPIRES_AT);
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(
        insertRegisterChallenge(CHALLENGE_VALUE, USER_ID, new Date())
      ).resolves.toBeUndefined();
    });
  });

  describe('insertRecoverChallenge', () => {
    it('executes INSERT with correct value, purpose=recover, userId, and expiresAt', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await insertRecoverChallenge(CHALLENGE_VALUE, USER_ID, EXPIRES_AT);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args[1]).toBe(CHALLENGE_VALUE);
      expect(args[2]).toBe(CHALLENGE_PURPOSE.RECOVER);
      expect(args[3]).toBe(USER_ID);
      expect(args[4]).toBe(EXPIRES_AT);
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(
        insertRecoverChallenge(CHALLENGE_VALUE, USER_ID, new Date())
      ).resolves.toBeUndefined();
    });
  });

  describe('insertLoginChallenge', () => {
    it('executes INSERT with correct value, purpose=login, and expiresAt (no userId)', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await insertLoginChallenge(CHALLENGE_VALUE, EXPIRES_AT);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args[1]).toBe(CHALLENGE_VALUE);
      expect(args[2]).toBe(CHALLENGE_PURPOSE.LOGIN);
      expect(args[3]).toBe(EXPIRES_AT);
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(insertLoginChallenge(CHALLENGE_VALUE, new Date())).resolves.toBeUndefined();
    });
  });

  describe('insertSessionChallenge', () => {
    it('executes INSERT with correct value, purpose=session, deviceId, and expiresAt', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await insertSessionChallenge(CHALLENGE_VALUE, DEVICE_ID, EXPIRES_AT);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args[1]).toBe(CHALLENGE_VALUE);
      expect(args[2]).toBe(CHALLENGE_PURPOSE.SESSION);
      expect(args[3]).toBe(DEVICE_ID);
      expect(args[4]).toBe(EXPIRES_AT);
    });

    it('resolves to void on success', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(
        insertSessionChallenge(CHALLENGE_VALUE, DEVICE_ID, new Date())
      ).resolves.toBeUndefined();
    });
  });

  describe('consumeRegisterChallenge', () => {
    it('returns true when UPDATE matches a row', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ value: CHALLENGE_VALUE }] as never);
      await expect(consumeRegisterChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(true);
    });

    it('returns false when no row matches', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRegisterChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(false);
    });

    it('returns false when challenge is already consumed', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRegisterChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(false);
    });

    it('returns false when challenge is expired', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRegisterChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(false);
    });

    it('returns false when userId does not match', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRegisterChallenge(CHALLENGE_VALUE, 'other-user')).resolves.toBe(false);
    });

    it('passes value and userId to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await consumeRegisterChallenge(CHALLENGE_VALUE, USER_ID);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([CHALLENGE_VALUE, USER_ID]));
    });
  });

  describe('consumeRecoverChallenge', () => {
    it('returns true when UPDATE matches a row', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ value: CHALLENGE_VALUE }] as never);
      await expect(consumeRecoverChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(true);
    });

    it('returns false when no row matches', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRecoverChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(false);
    });

    it('returns false when challenge is already consumed', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRecoverChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(false);
    });

    it('returns false when challenge is expired', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRecoverChallenge(CHALLENGE_VALUE, USER_ID)).resolves.toBe(false);
    });

    it('returns false when userId does not match', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeRecoverChallenge(CHALLENGE_VALUE, 'other-user')).resolves.toBe(false);
    });

    it('passes value and userId to the query', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await consumeRecoverChallenge(CHALLENGE_VALUE, USER_ID);
      const args = vi.mocked(sql).mock.calls[0];
      expect(args).toEqual(expect.arrayContaining([CHALLENGE_VALUE, USER_ID]));
    });
  });

  describe('consumeLoginChallenge', () => {
    it('returns true when UPDATE matches a row', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ value: CHALLENGE_VALUE }] as never);
      await expect(consumeLoginChallenge(CHALLENGE_VALUE)).resolves.toBe(true);
    });

    it('returns false when no row matches', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeLoginChallenge(CHALLENGE_VALUE)).resolves.toBe(false);
    });

    it('returns false when challenge is already consumed', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeLoginChallenge(CHALLENGE_VALUE)).resolves.toBe(false);
    });

    it('returns false when challenge is expired', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeLoginChallenge(CHALLENGE_VALUE)).resolves.toBe(false);
    });
  });

  describe('consumeSessionChallenge', () => {
    it('returns the row { device_id } when UPDATE matches', async () => {
      vi.mocked(sql).mockResolvedValueOnce([{ device_id: DEVICE_ID }] as never);
      await expect(consumeSessionChallenge(CHALLENGE_VALUE)).resolves.toEqual({
        device_id: DEVICE_ID,
      });
    });

    it('returns undefined when no row matches', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeSessionChallenge(CHALLENGE_VALUE)).resolves.toBeUndefined();
    });

    it('returns undefined when challenge is already consumed', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeSessionChallenge(CHALLENGE_VALUE)).resolves.toBeUndefined();
    });

    it('returns undefined when challenge is expired', async () => {
      vi.mocked(sql).mockResolvedValueOnce([] as never);
      await expect(consumeSessionChallenge(CHALLENGE_VALUE)).resolves.toBeUndefined();
    });
  });
});

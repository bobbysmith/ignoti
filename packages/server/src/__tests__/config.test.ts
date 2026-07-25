import { afterEach, describe, expect, it, vi } from 'vitest';

const VALID_DB_URL = 'postgresql://user:pass@localhost:5432/ghostid';
const VALID_ORIGIN = 'http://localhost:5173';
const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace'] as const;
const MOCK_URL = 'https://app.example.com';
const MOCK_STAGING_URL = 'https://staging.example.com';

function stubEnv(overrides: Record<string, string> = {}) {
  vi.stubEnv('DATABASE_URL', VALID_DB_URL);
  vi.stubEnv('RP_ORIGIN', VALID_ORIGIN);
  for (const [key, value] of Object.entries(overrides)) {
    vi.stubEnv(key, value);
  }
}

/**
 * Dynamically imports config after env has been set up.
 * Always call stubEnv() first so the required fields are present.
 */
async function loadConfig() {
  const { config } = await import('../config.js');
  return config;
}

describe('config', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  describe('DATABASE_URL', () => {
    it('throws when DATABASE_URL is missing', async () => {
      await expect(loadConfig()).rejects.toThrow();
    });

    it('throws when DATABASE_URL is not a valid URL', async () => {
      stubEnv({ DATABASE_URL: 'fakeUrl' });
      await expect(loadConfig()).rejects.toThrow();
    });

    it('accepts a valid postgresql:// connection string', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.DATABASE_URL).toBe(VALID_DB_URL);
    });
  });

  describe('PORT', () => {
    it('defaults to 8787 when PORT is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.PORT).toBe(8787);
    });

    it('coerces a PORT string to a number', async () => {
      stubEnv({ PORT: '3000' });
      const config = await loadConfig();
      expect(config.PORT).toBe(3000);
    });
  });

  describe('HOST', () => {
    it('defaults to "0.0.0.0" when HOST is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.HOST).toBe('0.0.0.0');
    });

    it('uses the provided HOST value', async () => {
      stubEnv({ HOST: '127.0.0.1' });
      const config = await loadConfig();
      expect(config.HOST).toBe('127.0.0.1');
    });
  });

  describe('DB_PREPARE', () => {
    it('defaults to true when DB_PREPARE is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.DB_PREPARE).toBe(true);
    });

    it('parses "false" as boolean false (case-insensitive)', async () => {
      for (const value of ['false', 'False', 'FALSE', 'fAlSe']) {
        vi.resetModules();
        stubEnv({ DB_PREPARE: value });
        const config = await loadConfig();
        expect(config.DB_PREPARE, `expected false for DB_PREPARE="${value}"`).toBe(false);
      }
    });

    it('parses any non-"false" string as true', async () => {
      for (const value of ['true', 'TRUE', '1', 'yes', 'on']) {
        vi.resetModules();
        stubEnv({ DB_PREPARE: value });
        const config = await loadConfig();
        expect(config.DB_PREPARE, `expected true for DB_PREPARE="${value}"`).toBe(true);
      }
    });
  });

  describe('RP_ORIGIN', () => {
    it('parses a single origin into a one-element array', async () => {
      stubEnv({ RP_ID: 'example.com', RP_ORIGIN: MOCK_URL });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual([MOCK_URL]);
    });

    it('defaults to [VALID_ORIGIN] when RP_ORIGIN is not set', async () => {
      // Stub only DATABASE_URL — do not set RP_ORIGIN.
      vi.stubEnv('DATABASE_URL', VALID_DB_URL);
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual([VALID_ORIGIN]);
    });

    it('splits a comma-separated list into multiple origins', async () => {
      stubEnv({
        RP_ID: 'example.com',
        RP_ORIGIN: 'https://app.example.com,https://staging.example.com',
      });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual([MOCK_URL, MOCK_STAGING_URL]);
    });

    it('trims whitespace around each entry', async () => {
      stubEnv({
        RP_ID: 'example.com',
        RP_ORIGIN: '  https://app.example.com  ,  https://staging.example.com  ',
      });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual([MOCK_URL, MOCK_STAGING_URL]);
    });

    it('filters out empty entries produced by trailing commas', async () => {
      stubEnv({
        RP_ID: 'example.com',
        RP_ORIGIN: 'https://app.example.com,,https://staging.example.com,',
      });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual([MOCK_URL, MOCK_STAGING_URL]);
    });

    it('throws when any origin is not a valid URL', async () => {
      stubEnv({ RP_ORIGIN: 'https://valid.example.com,not-a-url' });
      await expect(loadConfig()).rejects.toThrow();
    });

    it('throws when the single origin value is not a valid URL', async () => {
      stubEnv({ RP_ORIGIN: 'not-a-url' });
      await expect(loadConfig()).rejects.toThrow();
    });
  });

  describe('CHALLENGE_TTL_SECONDS', () => {
    it('defaults to 300 when CHALLENGE_TTL_SECONDS is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.CHALLENGE_TTL_SECONDS).toBe(300);
    });

    it('coerces a string value to a number', async () => {
      stubEnv({ CHALLENGE_TTL_SECONDS: '600' });
      const config = await loadConfig();
      expect(config.CHALLENGE_TTL_SECONDS).toBe(600);
    });
  });

  describe('SESSION_TTL_SECONDS', () => {
    it('defaults to 86400 (24 hours) when SESSION_TTL_SECONDS is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.SESSION_TTL_SECONDS).toBe(86400);
    });

    it('coerces a string value to a number', async () => {
      stubEnv({ SESSION_TTL_SECONDS: '3600' });
      const config = await loadConfig();
      expect(config.SESSION_TTL_SECONDS).toBe(3600);
    });
  });

  describe('GC_INTERVAL_SECONDS', () => {
    it('defaults to 3600 (1 hour) when GC_INTERVAL_SECONDS is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.GC_INTERVAL_SECONDS).toBe(3600);
    });

    it('accepts 0 to disable in-process GC', async () => {
      stubEnv({ GC_INTERVAL_SECONDS: '0' });
      const config = await loadConfig();
      expect(config.GC_INTERVAL_SECONDS).toBe(0);
    });

    it('throws when GC_INTERVAL_SECONDS exceeds one day', async () => {
      stubEnv({ GC_INTERVAL_SECONDS: String(60 * 60 * 24 + 1) });
      await expect(loadConfig()).rejects.toThrow();
    });
  });

  describe('LOG_LEVEL', () => {
    it('defaults to "info" when LOG_LEVEL is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.LOG_LEVEL).toBe('info');
    });

    it.each(LOG_LEVELS)('accepts "%s" as a valid log level', async level => {
      stubEnv({ LOG_LEVEL: level });
      const config = await loadConfig();
      expect(config.LOG_LEVEL).toBe(level);
    });

    it('throws when LOG_LEVEL is not a valid enum value', async () => {
      stubEnv({ LOG_LEVEL: 'verbose' });
      await expect(loadConfig()).rejects.toThrow();
    });
  });

  describe('RP_ID', () => {
    it('defaults to "localhost" when RP_ID is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.RP_ID).toBe('localhost');
    });

    it('uses the provided RP_ID value', async () => {
      stubEnv({ RP_ID: 'app.example.com', RP_ORIGIN: 'https://app.example.com' });
      const config = await loadConfig();
      expect(config.RP_ID).toBe('app.example.com');
    });
  });

  describe('RP_NAME', () => {
    it('defaults to "GhostID" when RP_NAME is not set', async () => {
      stubEnv();
      const config = await loadConfig();
      expect(config.RP_NAME).toBe('GhostID');
    });

    it('uses the provided RP_NAME value', async () => {
      stubEnv({ RP_NAME: 'My App' });
      const config = await loadConfig();
      expect(config.RP_NAME).toBe('My App');
    });
  });

  describe('RP_ID/RP_ORIGIN cross-validation', () => {
    it('accepts an origin whose hostname matches RP_ID exactly', async () => {
      stubEnv({ RP_ID: 'example.com', RP_ORIGIN: 'https://example.com' });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual(['https://example.com']);
    });

    it('accepts an origin whose hostname is a subdomain of RP_ID', async () => {
      stubEnv({ RP_ID: 'example.com', RP_ORIGIN: 'https://app.example.com' });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual(['https://app.example.com']);
    });

    it('accepts multiple subdomains of the same RP_ID', async () => {
      stubEnv({
        RP_ID: 'example.com',
        RP_ORIGIN: 'https://app.example.com,https://admin.example.com',
      });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toHaveLength(2);
    });

    it('throws when an origin hostname does not derive from RP_ID', async () => {
      stubEnv({ RP_ID: 'example.com', RP_ORIGIN: 'https://other.com' });
      await expect(loadConfig()).rejects.toThrow(/derive from RP_ID/);
    });

    it('throws when one origin in a list does not derive from RP_ID', async () => {
      stubEnv({
        RP_ID: 'example.com',
        RP_ORIGIN: 'https://app.example.com,https://attacker.com',
      });
      await expect(loadConfig()).rejects.toThrow(/derive from RP_ID/);
    });

    it('rejects a near-miss where the suffix matches without a dot boundary', async () => {
      stubEnv({ RP_ID: 'example.com', RP_ORIGIN: 'https://notexample.com' });
      await expect(loadConfig()).rejects.toThrow(/derive from RP_ID/);
    });

    it('accepts localhost when RP_ID is localhost', async () => {
      stubEnv({ RP_ID: 'localhost', RP_ORIGIN: 'http://localhost:5173' });
      const config = await loadConfig();
      expect(config.RP_ORIGIN).toEqual(['http://localhost:5173']);
    });
  });
});

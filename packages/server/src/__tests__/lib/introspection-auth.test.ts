import { afterEach, describe, expect, it, vi } from 'vitest';

async function load(secret: string | undefined) {
  vi.doMock('../../config.js', () => ({ config: { INTROSPECTION_SECRET: secret } }));
  return import('../../lib/introspection-auth.js');
}

describe('createIntrospectionAuth', () => {
  afterEach(() => {
    vi.resetModules();
  });

  it('throws when INTROSPECTION_SECRET is not configured', async () => {
    const { createIntrospectionAuth } = await load(undefined);
    expect(() => createIntrospectionAuth()).toThrow('INTROSPECTION_SECRET is required');
  });

  it('returns a hook when INTROSPECTION_SECRET is configured', async () => {
    const { createIntrospectionAuth } = await load('a'.repeat(32));
    expect(createIntrospectionAuth()).toBeTypeOf('function');
  });
});

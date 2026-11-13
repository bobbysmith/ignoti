import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createSessionKeyStore } from '@/core/session-key-store.ts';

const SCOPE = 'https://auth.example.com';

type Failure = 'open' | 'get' | 'put' | 'delete' | 'abort';

/**
 * Minimal in-memory IndexedDB: one database, one object store, and the
 * request/transaction events the key store relies on.
 */
function installFakeIndexedDB() {
  const records = new Map<string, unknown>();
  const state = {
    records,
    failures: new Set<Failure>(),
    storeCreated: false,
    opens: 0,
    closes: 0,
  };

  function request<T>(tx: Record<string, unknown>, kind: Failure, produce: () => T) {
    const req: Record<string, unknown> = {};
    queueMicrotask(() => {
      if (state.failures.has(kind)) {
        tx.error = new Error(`${kind} failed`);
        (tx.onerror as (() => void) | undefined)?.();
        return;
      }
      if (state.failures.has('abort')) {
        tx.error = new Error('aborted');
        (tx.onabort as (() => void) | undefined)?.();
        return;
      }
      req.result = produce();
      (tx.oncomplete as (() => void) | undefined)?.();
    });
    return req;
  }

  const db = {
    createObjectStore: () => {
      state.storeCreated = true;
    },
    close: () => {
      state.closes++;
    },
    transaction: () => {
      const tx: Record<string, unknown> = {};
      tx.objectStore = () => ({
        get: (key: string) => request(tx, 'get', () => records.get(key)),
        put: (value: unknown, key: string) =>
          request(tx, 'put', () => {
            records.set(key, value);
            return key;
          }),
        delete: (key: string) =>
          request(tx, 'delete', () => {
            records.delete(key);
            return undefined;
          }),
      });
      return tx;
    },
  };

  vi.stubGlobal('indexedDB', {
    open: () => {
      state.opens++;
      const req: Record<string, unknown> = {};
      queueMicrotask(() => {
        if (state.failures.has('open')) {
          req.error = new Error('open failed');
          (req.onerror as () => void)();
          return;
        }
        req.result = db;
        if (!state.storeCreated) {
          (req.onupgradeneeded as () => void)();
        }
        (req.onsuccess as () => void)();
      });
      return req;
    },
  });

  return state;
}

async function makeKeyPair(extractable = false): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: 'Ed25519' }, extractable, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}

describe('session key store', () => {
  let idb: ReturnType<typeof installFakeIndexedDB>;

  beforeEach(() => {
    idb = installFakeIndexedDB();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns null when nothing is stored', async () => {
    await expect(createSessionKeyStore(SCOPE).load()).resolves.toBeNull();
  });

  it('creates the object store on first open only', async () => {
    const store = createSessionKeyStore(SCOPE);
    await store.load();
    expect(idb.storeCreated).toBe(true);
    await store.load();
    expect(idb.opens).toBe(2);
  });

  it('returns the same keypair it saved', async () => {
    const store = createSessionKeyStore(SCOPE);
    const keyPair = await makeKeyPair();
    await expect(store.save(keyPair)).resolves.toBe(true);
    const loaded = await store.load();
    expect(loaded?.privateKey).toBe(keyPair.privateKey);
    expect(loaded?.publicKey).toBe(keyPair.publicKey);
  });

  it('replaces the previous keypair on save', async () => {
    const store = createSessionKeyStore(SCOPE);
    await store.save(await makeKeyPair());
    const second = await makeKeyPair();
    await store.save(second);
    expect((await store.load())?.privateKey).toBe(second.privateKey);
    expect(idb.records.size).toBe(1);
  });

  it('keeps keypairs for different scopes apart', async () => {
    const first = createSessionKeyStore(SCOPE);
    const second = createSessionKeyStore('https://other.example.com');
    const firstPair = await makeKeyPair();
    const secondPair = await makeKeyPair();
    await first.save(firstPair);
    await second.save(secondPair);
    expect((await first.load())?.privateKey).toBe(firstPair.privateKey);
    expect((await second.load())?.privateKey).toBe(secondPair.privateKey);
    await first.clear();
    await expect(first.load()).resolves.toBeNull();
    expect((await second.load())?.privateKey).toBe(secondPair.privateKey);
  });

  it('removes the keypair on clear', async () => {
    const store = createSessionKeyStore(SCOPE);
    await store.save(await makeKeyPair());
    await store.clear();
    await expect(store.load()).resolves.toBeNull();
    expect(idb.records.size).toBe(0);
  });

  it('closes the database after every operation', async () => {
    const store = createSessionKeyStore(SCOPE);
    await store.save(await makeKeyPair());
    await store.load();
    await store.clear();
    expect(idb.closes).toBe(idb.opens);
  });

  it.each([
    ['a non-object', 'not a keypair'],
    ['an object without keys', {}],
    ['a keypair missing its public key', { privateKey: { type: 'private', extractable: false } }],
  ])('ignores a stored value that is %s', async (_label, value) => {
    idb.records.set(SCOPE, value);
    await expect(createSessionKeyStore(SCOPE).load()).resolves.toBeNull();
  });

  it('ignores a stored keypair whose private key is extractable', async () => {
    idb.records.set(SCOPE, await makeKeyPair(true));
    await expect(createSessionKeyStore(SCOPE).load()).resolves.toBeNull();
  });

  it('ignores a stored keypair whose halves are swapped', async () => {
    const { privateKey, publicKey } = await makeKeyPair();
    idb.records.set(SCOPE, { privateKey: publicKey, publicKey: privateKey });
    await expect(createSessionKeyStore(SCOPE).load()).resolves.toBeNull();
  });

  describe('when storage fails', () => {
    it.each<Failure>([
      'open',
      'get',
      'abort',
    ])('load resolves null on a %s failure', async failure => {
      idb.records.set(SCOPE, await makeKeyPair());
      idb.failures.add(failure);
      await expect(createSessionKeyStore(SCOPE).load()).resolves.toBeNull();
    });

    it('save resolves false and leaves no stale keypair behind', async () => {
      const store = createSessionKeyStore(SCOPE);
      await store.save(await makeKeyPair());
      idb.failures.add('put');
      await expect(store.save(await makeKeyPair())).resolves.toBe(false);
      idb.failures.clear();
      await expect(store.load()).resolves.toBeNull();
    });

    it('save resolves false when the database cannot be opened', async () => {
      idb.failures.add('open');
      await expect(createSessionKeyStore(SCOPE).save(await makeKeyPair())).resolves.toBe(false);
    });

    it('clear never rejects', async () => {
      idb.failures.add('delete');
      await expect(createSessionKeyStore(SCOPE).clear()).resolves.toBeUndefined();
    });

    it('every operation is safe when indexedDB does not exist', async () => {
      vi.unstubAllGlobals();
      const store = createSessionKeyStore(SCOPE);
      await expect(store.load()).resolves.toBeNull();
      await expect(store.save(await makeKeyPair())).resolves.toBe(false);
      await expect(store.clear()).resolves.toBeUndefined();
    });
  });
});

/**
 * Persists the session signing keypair across page reloads.
 *
 * The private key is a non-extractable CryptoKey: IndexedDB stores the key
 * handle by structured clone, so page script can use it but never read its
 * bytes. Every operation is best-effort. When IndexedDB is unavailable the
 * session still works but does not survive a reload.
 */

const DB_NAME = 'ignoti';
const STORE_NAME = 'session';

export interface SessionKeyStore {
  /** Resolves null when nothing is stored or storage is unavailable. */
  load(): Promise<CryptoKeyPair | null>;
  /** Resolves false when the keypair could not be stored; nothing is left stored. */
  save(keyPair: CryptoKeyPair): Promise<boolean>;
  clear(): Promise<void>;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function run<T>(
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> {
  const db = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, mode);
      const request = operation(tx.objectStore(STORE_NAME));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

function isKeyPair(value: unknown): value is CryptoKeyPair {
  const pair = value as Partial<CryptoKeyPair> | null | undefined;
  return (
    pair?.privateKey?.type === 'private' &&
    pair.privateKey.extractable === false &&
    pair.publicKey?.type === 'public'
  );
}

/** `scope` names the record, so sessions on different Ignoti servers do not collide. */
export function createSessionKeyStore(scope: string): SessionKeyStore {
  const clear = async (): Promise<void> => {
    try {
      await run('readwrite', store => store.delete(scope));
    } catch {
      // Best-effort.
    }
  };

  return {
    async load() {
      try {
        const value = await run('readonly', store => store.get(scope));
        return isKeyPair(value) ? value : null;
      } catch {
        return null;
      }
    },

    async save(keyPair) {
      try {
        await run('readwrite', store => store.put(keyPair, scope));
        return true;
      } catch {
        // A stale keypair must not outlive a failed write.
        await clear();
        return false;
      }
    },

    clear,
  };
}

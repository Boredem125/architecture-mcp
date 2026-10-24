/**
 * Browser key storage.
 *
 * In the browser the key pair is stored in IndexedDB (non-extractable
 * private key stays in the WebCrypto key store; IndexedDB holds a
 * reference via structured clone).
 *
 * In a Node test environment (vitest), IndexedDB is unavailable so
 * an in-memory Map is used as a fallback.
 */

/** IndexedDB object store name for browser keys. */
export const KEY_STORE_NAME = "agg-browser-keys";

const DB_NAME = "agg-web";
const DB_VERSION = 1;

// In-memory fallback for Node (vitest) where IndexedDB is absent.
const _memStore = new Map<string, CryptoKeyPair>();

function hasIndexedDB(): boolean {
  return typeof indexedDB !== "undefined";
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
        db.createObjectStore(KEY_STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Store a key pair under the given key identifier.
 */
export async function storeKey(
  keyId: string,
  keyPair: CryptoKeyPair,
): Promise<void> {
  if (!hasIndexedDB()) {
    _memStore.set(keyId, keyPair);
    return;
  }
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE_NAME, "readwrite");
    const store = tx.objectStore(KEY_STORE_NAME);
    const req = store.put(keyPair, keyId);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

/**
 * Load a previously stored key pair by its key identifier.
 * Returns ``null`` when no key is found.
 */
export async function loadKey(
  keyId: string,
): Promise<CryptoKeyPair | null> {
  if (!hasIndexedDB()) {
    return _memStore.get(keyId) ?? null;
  }
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE_NAME, "readonly");
    const store = tx.objectStore(KEY_STORE_NAME);
    const req = store.get(keyId);
    req.onsuccess = () => resolve((req.result as CryptoKeyPair) ?? null);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

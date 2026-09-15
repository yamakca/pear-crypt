/** Fixed inputs for deterministic crypto test vectors (docs/crypto/vectors). */

export const VECTOR_SPEC_VERSION = '1.0.0';

export const FIXTURE_MASTER_KEY_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

export const FIXTURE_WRAP_SALT_HEX = '0123456789abcdef0123456789abcdef';

export const FIXTURE_IV_HEX = '0102030405060708090a0b0c';

export const FIXTURE_SHARE_KEY_HEX =
  '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f';

export const FIXTURE_FILE_UID = 'vector-file-uid-001';

export const FIXTURE_META_UID = 'vector-meta-uid-001';

export const FIXTURE_SHARE_PUBLIC_ID = 'vector-share-public-001';

export const FIXTURE_WRAP_PASSWORD = 'vector-wrap-password';

export const FIXTURE_DEMO_PASSWORD = 'vector-demo-pin';

export const FIXTURE_DEMO_PLAINTEXT = 'pear-crypt vector demo';

export const FIXTURE_FILE_PLAINTEXT_UTF8 = 'hello pear-crypt';

export const FIXTURE_BIND_AT = 42;

export const FIXTURE_RECOVERY_CODE = 'ABCDE-FGHJK-LMNPR-STUVW';

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/\s/g, '');
  if (normalized.length % 2 !== 0) {
    throw new Error('invalid hex');
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Queue for crypto.getRandomValues — each call fills the target buffer from the next chunk. */
export function withFixedRandom<T>(chunks: Uint8Array[], run: () => Promise<T>): Promise<T> {
  const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  const queue = chunks.map(chunk => new Uint8Array(chunk));

  globalThis.crypto.getRandomValues = (<T extends ArrayBufferView | null>(target: T): T => {
    if (target === null) {
      return target;
    }

    const view = new Uint8Array(
      target.buffer,
      target.byteOffset,
      target.byteLength,
    );
    const next = queue.shift();
    if (next) {
      view.set(next.subarray(0, view.length));
    } else {
      original(view);
    }

    return target;
  }) as typeof globalThis.crypto.getRandomValues;

  return run().finally(() => {
    globalThis.crypto.getRandomValues = original;
  });
}

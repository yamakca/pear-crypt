import { cryptoError } from './errors.ts';
import { E2EE_MASTER_KEY_BYTES } from './constants.ts';

function getSubtleCrypto(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw cryptoError('webCryptoUnavailable');
  }

  return globalThis.crypto.subtle;
}

export async function deriveFileKeyFromRaw(
  masterKeyRaw: Uint8Array,
  uid: string,
): Promise<CryptoKey> {
  return deriveScopedKeyFromRaw(masterKeyRaw, `pear-keep-file:${uid}`);
}

export async function deriveMetadataKeyFromRaw(
  masterKeyRaw: Uint8Array,
  uid: string,
): Promise<CryptoKey> {
  return deriveScopedKeyFromRaw(masterKeyRaw, `pear-keep-meta:${uid}`);
}

export async function deriveSettingsKeyFromRaw(
  masterKeyRaw: Uint8Array,
): Promise<CryptoKey> {
  return deriveScopedKeyFromRaw(masterKeyRaw, 'pear-keep-settings');
}

async function deriveScopedKeyFromRaw(
  masterKeyRaw: Uint8Array,
  scope: string,
): Promise<CryptoKey> {
  if (masterKeyRaw.byteLength !== E2EE_MASTER_KEY_BYTES) {
    throw cryptoError('invalidMasterKey');
  }

  const subtle = getSubtleCrypto();
  const info = new TextEncoder().encode(scope);
  const baseKey = await subtle.importKey(
    'raw',
    masterKeyRaw,
    'HKDF',
    false,
    ['deriveKey'],
  );

  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

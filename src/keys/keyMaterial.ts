import { cryptoError } from '../errors.ts';
import { AES_GCM_KEY_BITS, E2EE_MASTER_KEY_BYTES } from '../constants.ts';
import { requireSubtleCrypto } from '../webCrypto.ts';
import { exportMasterKeyRaw } from './masterKeyCrypto.ts';

/** HKDF salt is empty: domain separation is entirely in `info`. */
const HKDF_SALT = new Uint8Array(0);

const FILE_SCOPE_PREFIX = 'pear-keep-file:';
const METADATA_SCOPE_PREFIX = 'pear-keep-meta:';
const SETTINGS_SCOPE = 'pear-keep-settings';

export async function deriveFileKeyFromRaw(
  masterKeyRaw: Uint8Array,
  uid: string,
): Promise<CryptoKey> {
  return deriveScopedKeyFromRaw(masterKeyRaw, `${FILE_SCOPE_PREFIX}${uid}`);
}

export async function deriveMetadataKeyFromRaw(
  masterKeyRaw: Uint8Array,
  uid: string,
): Promise<CryptoKey> {
  return deriveScopedKeyFromRaw(masterKeyRaw, `${METADATA_SCOPE_PREFIX}${uid}`);
}

export async function deriveSettingsKeyFromRaw(masterKeyRaw: Uint8Array): Promise<CryptoKey> {
  return deriveScopedKeyFromRaw(masterKeyRaw, SETTINGS_SCOPE);
}

export async function deriveFileKey(masterKey: CryptoKey, uid: string): Promise<CryptoKey> {
  return deriveFileKeyFromRaw(await exportMasterKeyRaw(masterKey), uid);
}

export async function deriveMetadataKey(masterKey: CryptoKey, uid: string): Promise<CryptoKey> {
  return deriveMetadataKeyFromRaw(await exportMasterKeyRaw(masterKey), uid);
}

export async function deriveSettingsKey(masterKey: CryptoKey): Promise<CryptoKey> {
  return deriveSettingsKeyFromRaw(await exportMasterKeyRaw(masterKey));
}

async function deriveScopedKeyFromRaw(masterKeyRaw: Uint8Array, scope: string): Promise<CryptoKey> {
  const isMasterKeyLengthWrong = masterKeyRaw.byteLength !== E2EE_MASTER_KEY_BYTES;
  if (isMasterKeyLengthWrong) {
    throw cryptoError('invalidMasterKey');
  }

  const subtle = requireSubtleCrypto('webCryptoUnavailable');
  const info = new TextEncoder().encode(scope);
  const baseKey = await subtle.importKey('raw', masterKeyRaw, 'HKDF', false, ['deriveKey']);

  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info },
    baseKey,
    { name: 'AES-GCM', length: AES_GCM_KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

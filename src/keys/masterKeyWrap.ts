import { cryptoError, isPearKeepCryptoError } from '../errors.ts';
import { base64ToBytes, bytesToBase64 } from '../encoding.ts';
import {
  deriveFileKeyFromRaw,
  deriveMetadataKeyFromRaw,
  deriveSettingsKeyFromRaw,
} from '../keyMaterial.ts';
import { parseWrappedMasterKeyPayload } from '../jsonGuards.ts';
import type { E2eeKeyMaterial, WrappedMasterKeyPayload } from './types.ts';
import {
  decryptWithKey,
  deriveWrapKey,
  encryptWithKey,
  exportMasterKeyRaw,
  importMasterKeyRaw,
  isLegacyWrapPayload,
} from './masterKeyCrypto.ts';

export {
  exportMasterKeyRaw,
  generateMasterKey,
  generateSalt,
  importMasterKeyRaw,
  isLegacyWrapPayload,
} from './masterKeyCrypto.ts';

export { parseWrappedMasterKeyPayload } from '../jsonGuards.ts';

function readWrappedMasterKeyPayload(wrappedMasterKey: string): WrappedMasterKeyPayload {
  if (wrappedMasterKey.trim() === '') {
    throw cryptoError('corruptServerE2eeData');
  }

  try {
    return parseWrappedMasterKeyPayload(JSON.parse(wrappedMasterKey));
  } catch (error) {
    if (isPearKeepCryptoError(error, 'corruptServerE2eeData')) {
      throw error;
    }

    throw cryptoError('corruptServerE2eeData');
  }
}

export async function wrapMasterKey(
  masterKey: CryptoKey,
  password: string,
  salt: Uint8Array,
): Promise<{ keySalt: string, wrappedMasterKey: string }> {
  const passwordKey = await deriveWrapKey(password, salt, {
    v: 2,
    kdf: undefined,
  });
  const raw = await exportMasterKeyRaw(masterKey);
  const wrapped = await encryptWithKey(passwordKey, raw);

  return {
    keySalt: bytesToBase64(salt),
    wrappedMasterKey: JSON.stringify(wrapped),
  };
}

export async function unwrapMasterKey(
  password: string,
  material: E2eeKeyMaterial,
): Promise<CryptoKey> {
  if (!material.keySalt?.trim() || !material.wrappedMasterKey?.trim()) {
    throw cryptoError('corruptServerE2eeData');
  }

  try {
    const salt = base64ToBytes(material.keySalt);
    const payload = readWrappedMasterKeyPayload(material.wrappedMasterKey);
    const passwordKey = await deriveWrapKey(password, salt, payload);
    const raw = await decryptWithKey(passwordKey, payload);

    return importMasterKeyRaw(raw);
  } catch (error) {
    if (isPearKeepCryptoError(error, 'corruptServerE2eeData')) {
      throw error;
    }

    if (isPearKeepCryptoError(error, 'invalidEncoding')) {
      throw cryptoError('corruptServerE2eeData');
    }

    throw cryptoError('wrongPassword');
  }
}

export function wrappedMasterKeyNeedsKdfUpgrade(wrappedMasterKey: string): boolean {
  try {
    return isLegacyWrapPayload(readWrappedMasterKeyPayload(wrappedMasterKey));
  } catch {
    return false;
  }
}

export async function deriveFileKey(masterKey: CryptoKey, uid: string): Promise<CryptoKey> {
  const raw = await exportMasterKeyRaw(masterKey);
  return deriveFileKeyFromRaw(raw, uid);
}

export async function deriveMetadataKey(masterKey: CryptoKey, uid: string): Promise<CryptoKey> {
  const raw = await exportMasterKeyRaw(masterKey);
  return deriveMetadataKeyFromRaw(raw, uid);
}

export async function deriveSettingsKey(masterKey: CryptoKey): Promise<CryptoKey> {
  const raw = await exportMasterKeyRaw(masterKey);
  return deriveSettingsKeyFromRaw(raw);
}

export async function rewrapMasterKey(
  masterKey: CryptoKey,
  password: string,
  keySalt: string,
): Promise<string> {
  const salt = base64ToBytes(keySalt);
  const wrapped = await wrapMasterKey(masterKey, password, salt);

  return wrapped.wrappedMasterKey;
}

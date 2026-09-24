import { E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID } from '../constants.ts';
import { cryptoError, isPearKeepCryptoError } from '../errors.ts';
import { base64ToBytes, bytesToBase64 } from '../encoding.ts';
import { parseWrappedMasterKeyPayload } from './payload.ts';
import type { E2eeKeyMaterial, WrappedMasterKeyPayload } from './types.ts';
import {
  decryptWithKey,
  deriveWrapKey,
  encryptWithKey,
  exportMasterKeyRaw,
  importMasterKeyRaw,
  isLegacyWrapPayload,
} from './masterKeyCrypto.ts';

function readWrappedMasterKeyPayload(wrappedMasterKey: string): WrappedMasterKeyPayload {
  const isWrappedKeyBlank = wrappedMasterKey.trim() === '';
  if (isWrappedKeyBlank) {
    throw cryptoError('corruptServerE2eeData');
  }

  try {
    return parseWrappedMasterKeyPayload(JSON.parse(wrappedMasterKey));
  } catch (error) {
    const isCorruptServerData = isPearKeepCryptoError(error, 'corruptServerE2eeData');
    if (isCorruptServerData) {
      throw error;
    }

    throw cryptoError('corruptServerE2eeData');
  }
}

export async function wrapMasterKey(
  masterKey: CryptoKey,
  password: string,
  salt: Uint8Array,
): Promise<{ keySalt: string; wrappedMasterKey: string }> {
  const passwordKey = await deriveWrapKey(password, salt, {
    v: E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID,
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
  const hasKeySalt = Boolean(material.keySalt?.trim());
  const hasWrappedMasterKey = Boolean(material.wrappedMasterKey?.trim());
  if (!hasKeySalt || !hasWrappedMasterKey) {
    throw cryptoError('corruptServerE2eeData');
  }

  try {
    const salt = base64ToBytes(material.keySalt);
    const payload = readWrappedMasterKeyPayload(material.wrappedMasterKey);
    const passwordKey = await deriveWrapKey(password, salt, payload);
    const raw = await decryptWithKey(passwordKey, payload);

    return importMasterKeyRaw(raw);
  } catch (error) {
    const isCorruptServerData = isPearKeepCryptoError(error, 'corruptServerE2eeData');
    if (isCorruptServerData) {
      throw error;
    }

    const isBadEncoding = isPearKeepCryptoError(error, 'invalidEncoding');
    if (isBadEncoding) {
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

export async function rewrapMasterKey(
  masterKey: CryptoKey,
  password: string,
  keySalt: string,
): Promise<string> {
  const salt = base64ToBytes(keySalt);
  const wrapped = await wrapMasterKey(masterKey, password, salt);

  return wrapped.wrappedMasterKey;
}

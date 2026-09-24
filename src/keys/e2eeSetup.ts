import { cryptoError, isPearKeepCryptoError } from '../errors.ts';
import { base64ToBytes, bytesToBase64 } from '../encoding.ts';
import { generateRecoveryCode, normalizeRecoveryCode } from '../recovery/code.ts';
import { parseRecoveryWrapEnvelope } from '../recovery/envelope.ts';
import { E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID, E2EE_WRAP_VERSION_VAULT } from '../constants.ts';
import { parseWrappedMasterKeyPayload } from './payload.ts';
import type { E2eeKeyMaterial } from './types.ts';
import {
  decryptWithKey,
  deriveWrapKey,
  encryptWithKey,
  exportMasterKeyRaw,
  generateMasterKey,
  generateSalt,
  importMasterKeyRaw,
} from './masterKeyCrypto.ts';
import { wrapMasterKey } from './masterKeyWrap.ts';

export async function createRecoveryWrap(masterKey: CryptoKey): Promise<{
  recoveryCode: string;
  recoveryWrappedMasterKey: string;
}> {
  const recoveryCode = generateRecoveryCode();
  const recoverySalt = generateSalt();
  const recoveryPasswordKey = await deriveWrapKey(
    normalizeRecoveryCode(recoveryCode),
    recoverySalt,
    { v: E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID },
  );
  const recoveryRaw = await exportMasterKeyRaw(masterKey);
  const recoveryPayload = await encryptWithKey(recoveryPasswordKey, recoveryRaw);
  const recoveryWrappedMasterKey = JSON.stringify({
    salt: bytesToBase64(recoverySalt),
    wrapped: JSON.stringify(recoveryPayload),
  });

  return {
    recoveryCode,
    recoveryWrappedMasterKey,
  };
}

export async function createE2eeSetup(
  password: string,
  keyVersion: number = E2EE_WRAP_VERSION_VAULT,
): Promise<{
  masterKey: CryptoKey;
  material: E2eeKeyMaterial;
  recoveryCode: string;
}> {
  const salt = generateSalt();
  const masterKey = await generateMasterKey();
  const wrapped = await wrapMasterKey(masterKey, password, salt);
  const recovery = await createRecoveryWrap(masterKey);

  return {
    masterKey,
    recoveryCode: recovery.recoveryCode,
    material: {
      keySalt: wrapped.keySalt,
      wrappedMasterKey: wrapped.wrappedMasterKey,
      keyVersion,
      recoveryWrappedMasterKey: recovery.recoveryWrappedMasterKey,
    },
  };
}

export async function unwrapMasterKeyWithRecovery(
  recoveryCode: string,
  recoveryWrappedMasterKey: string,
): Promise<CryptoKey> {
  const isRecoveryWrapBlank = recoveryWrappedMasterKey.trim() === '';
  if (isRecoveryWrapBlank) {
    throw cryptoError('corruptRecoveryData');
  }

  let envelope: ReturnType<typeof parseRecoveryWrapEnvelope>;
  try {
    envelope = parseRecoveryWrapEnvelope(JSON.parse(recoveryWrappedMasterKey));
  } catch (error) {
    const isCorruptRecoveryData = isPearKeepCryptoError(error, 'corruptRecoveryData');
    if (isCorruptRecoveryData) {
      throw error;
    }

    throw cryptoError('corruptRecoveryData');
  }

  try {
    const salt = base64ToBytes(envelope.salt);
    const payload = parseWrappedMasterKeyPayload(JSON.parse(envelope.wrapped));

    const passwordKey = await deriveWrapKey(normalizeRecoveryCode(recoveryCode), salt, payload);
    const raw = await decryptWithKey(passwordKey, payload);

    return importMasterKeyRaw(raw);
  } catch (error) {
    const isCorruptRecoveryData = isPearKeepCryptoError(error, 'corruptRecoveryData');
    if (isCorruptRecoveryData) {
      throw error;
    }

    throw cryptoError('invalidRecoveryCode');
  }
}

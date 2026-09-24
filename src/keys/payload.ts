import { E2EE_WRAP_PAYLOAD_VERSION_PBKDF2 } from '../constants.ts';
import { cryptoError } from '../errors.ts';
import { isNonEmptyString, isRecord } from '../json.ts';
import type { WrappedMasterKeyPayload, WrapKdfParams } from './types.ts';

function isWrapKdfParams(value: unknown): value is WrapKdfParams {
  const isParamsObject = isRecord(value);
  if (!isParamsObject) {
    return false;
  }

  const isArgon2id = value.alg === 'argon2id';
  const hasMemoryCost = typeof value.m === 'number';
  const hasIterations = typeof value.t === 'number';
  const hasParallelism = typeof value.p === 'number';

  return isArgon2id && hasMemoryCost && hasIterations && hasParallelism;
}

export function parseWrappedMasterKeyPayload(value: unknown): WrappedMasterKeyPayload {
  const isPayloadObject = isRecord(value);
  if (!isPayloadObject) {
    throw cryptoError('corruptServerE2eeData');
  }

  const iv = value.iv;
  const hasIv = isNonEmptyString(iv);
  if (!hasIv) {
    throw cryptoError('corruptServerE2eeData');
  }

  const data = value.data;
  const hasData = isNonEmptyString(data);
  if (!hasData) {
    throw cryptoError('corruptServerE2eeData');
  }

  const versionValue = value.v;
  const hasNumericVersion = typeof versionValue === 'number';
  const version = hasNumericVersion ? versionValue : E2EE_WRAP_PAYLOAD_VERSION_PBKDF2;
  const payload: WrappedMasterKeyPayload = {
    v: version,
    iv,
    data,
  };

  const kdf = value.kdf;
  const hasKdf = kdf !== undefined;
  if (hasKdf) {
    const isKdfValid = isWrapKdfParams(kdf);
    if (!isKdfValid) {
      throw cryptoError('corruptServerE2eeData');
    }

    payload.kdf = kdf;
  }

  return payload;
}

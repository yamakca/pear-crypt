import { cryptoError } from '../errors.ts';
import { isNonEmptyString, isRecord } from '../json.ts';

export interface RecoveryWrapEnvelope {
  salt: string;
  wrapped: string;
}

export function parseRecoveryWrapEnvelope(value: unknown): RecoveryWrapEnvelope {
  const isEnvelopeObject = isRecord(value);
  if (!isEnvelopeObject) {
    throw cryptoError('corruptRecoveryData');
  }

  const salt = value.salt;
  const hasSalt = isNonEmptyString(salt);
  if (!hasSalt) {
    throw cryptoError('corruptRecoveryData');
  }

  const wrapped = value.wrapped;
  const hasWrappedKey = isNonEmptyString(wrapped);
  if (!hasWrappedKey) {
    throw cryptoError('corruptRecoveryData');
  }

  return {
    salt,
    wrapped,
  };
}

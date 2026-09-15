import { cryptoError } from './errors.ts';
import type { WrappedMasterKeyPayload, WrapKdfParams } from './keys/types.ts';
import type { FileMetadataPlaintext } from './metadata.ts';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== '';
}

function isWrapKdfParams(value: unknown): value is WrapKdfParams {
  if (!isRecord(value)) {
    return false;
  }

  return value.alg === 'argon2id'
    && typeof value.m === 'number'
    && typeof value.t === 'number'
    && typeof value.p === 'number';
}

export function parseWrappedMasterKeyPayload(value: unknown): WrappedMasterKeyPayload {
  if (!isRecord(value)) {
    throw cryptoError('corruptServerE2eeData');
  }

  if (!isNonEmptyString(value.iv) || !isNonEmptyString(value.data)) {
    throw cryptoError('corruptServerE2eeData');
  }

  const payload: WrappedMasterKeyPayload = {
    v: typeof value.v === 'number' ? value.v : 1,
    iv: value.iv,
    data: value.data,
  };

  if (value.kdf !== undefined) {
    if (!isWrapKdfParams(value.kdf)) {
      throw cryptoError('corruptServerE2eeData');
    }

    payload.kdf = value.kdf;
  }

  return payload;
}

export interface RecoveryWrapEnvelope {
  salt: string;
  wrapped: string;
}

export function parseRecoveryWrapEnvelope(value: unknown): RecoveryWrapEnvelope {
  if (!isRecord(value)) {
    throw cryptoError('corruptRecoveryData');
  }

  if (!isNonEmptyString(value.salt) || !isNonEmptyString(value.wrapped)) {
    throw cryptoError('corruptRecoveryData');
  }

  return {
    salt: value.salt,
    wrapped: value.wrapped,
  };
}

interface ShareEnvelopeHeaderJson {
  filename: string;
  mime?: string;
}

export function parseShareEnvelopeHeader(value: unknown): ShareEnvelopeHeaderJson {
  if (!isRecord(value) || !isNonEmptyString(value.filename)) {
    throw cryptoError('invalidShareEnvelope');
  }

  const header: ShareEnvelopeHeaderJson = { filename: value.filename };
  if (value.mime !== undefined) {
    if (typeof value.mime !== 'string') {
      throw cryptoError('invalidShareEnvelope');
    }

    header.mime = value.mime;
  }

  return header;
}

export function parseFileMetadataPlaintext(value: unknown): FileMetadataPlaintext {
  if (!isRecord(value) || typeof value.label !== 'string') {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  const metadata: FileMetadataPlaintext = { label: value.label };

  if (value.tags !== undefined) {
    if (typeof value.tags !== 'string') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.tags = value.tags;
  }

  if (value.comments !== undefined) {
    if (typeof value.comments !== 'string') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.comments = value.comments;
  }

  if (value.extension !== undefined) {
    if (typeof value.extension !== 'string') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.extension = value.extension;
  }

  if (value.marker !== undefined) {
    if (typeof value.marker !== 'string') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.marker = value.marker;
  }

  if (value.type !== undefined) {
    if (typeof value.type !== 'string') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.type = value.type;
  }

  if (value.contentUpdatedAt !== undefined) {
    if (typeof value.contentUpdatedAt !== 'number') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.contentUpdatedAt = value.contentUpdatedAt;
  }

  if (value.contentDigest !== undefined) {
    if (typeof value.contentDigest !== 'string') {
      throw cryptoError('invalidEncryptedMetadataFormat');
    }

    metadata.contentDigest = value.contentDigest;
  }

  return metadata;
}

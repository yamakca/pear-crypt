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

  const tags = optionalString(value.tags);
  if (tags !== undefined) {
    metadata.tags = tags;
  }

  const comments = optionalString(value.comments);
  if (comments !== undefined) {
    metadata.comments = comments;
  }

  const extension = optionalString(value.extension);
  if (extension !== undefined) {
    metadata.extension = extension;
  }

  const marker = optionalString(value.marker);
  if (marker !== undefined) {
    metadata.marker = marker;
  }

  const type = optionalString(value.type);
  if (type !== undefined) {
    metadata.type = type;
  }

  const contentUpdatedAt = optionalFiniteNumber(value.contentUpdatedAt);
  if (contentUpdatedAt !== undefined) {
    metadata.contentUpdatedAt = contentUpdatedAt;
  }

  const contentDigest = optionalString(value.contentDigest);
  if (contentDigest !== undefined) {
    metadata.contentDigest = contentDigest;
  }

  return metadata;
}

/** Treat JSON `null` like omitted — older clients wrote `"extension":null` etc. */
function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== 'string') {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  return value;
}

function optionalFiniteNumber(value: unknown): number | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  return value;
}

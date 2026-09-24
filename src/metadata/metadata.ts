import { cryptoError, isPearKeepCryptoError } from '../errors.ts';
import { AES_GCM_IV_BYTES, E2EE_BLOB_VERSION, E2EE_PLACEHOLDER_LABEL } from '../constants.ts';
import { bytesToBase64, base64ToBytes } from '../encoding.ts';
import { isRecord } from '../json.ts';
import { deriveMetadataKey } from '../keys/keyMaterial.ts';
import {
  encodeBlobAad,
  isE2eeBlobVersion,
  packVersionedBlob,
  readVersionedBlob,
} from '../wire/blobFrame.ts';

export interface FileMetadataPlaintext {
  label: string;
  tags?: string;
  comments?: string;
  extension?: string;
  marker?: string;
  type?: string;
  contentUpdatedAt?: number;
  contentDigest?: string;
}

export { E2EE_PLACEHOLDER_LABEL };

const OPTIONAL_TEXT_FIELDS = [
  'tags',
  'comments',
  'extension',
  'marker',
  'type',
  'contentDigest',
] as const;

export function parseFileMetadataPlaintext(value: unknown): FileMetadataPlaintext {
  const isMetadataObject = isRecord(value);
  if (!isMetadataObject) {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  const label = value.label;
  const hasStringLabel = typeof label === 'string';
  if (!hasStringLabel) {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  const metadata: FileMetadataPlaintext = { label };
  for (const field of OPTIONAL_TEXT_FIELDS) {
    const text = optionalString(value[field]);
    const hasText = text !== undefined;
    if (hasText) {
      metadata[field] = text;
    }
  }

  const contentUpdatedAt = optionalFiniteNumber(value.contentUpdatedAt);
  const hasContentUpdatedAt = contentUpdatedAt !== undefined;
  if (hasContentUpdatedAt) {
    metadata.contentUpdatedAt = contentUpdatedAt;
  }

  return metadata;
}

/** Treat JSON `null` and wrong types as omitted. Older clients wrote those. */
function optionalString(value: unknown): string | undefined {
  const isMissing = value === undefined;
  const isNull = value === null;
  if (isMissing || isNull) {
    return undefined;
  }

  const isString = typeof value === 'string';

  return isString ? value : undefined;
}

function optionalFiniteNumber(value: unknown): number | undefined {
  const isMissing = value === undefined;
  const isNull = value === null;
  if (isMissing || isNull) {
    return undefined;
  }

  const isNumber = typeof value === 'number';
  const isFiniteNumber = isNumber && Number.isFinite(value);
  if (isFiniteNumber) {
    return value;
  }

  const isString = typeof value === 'string';
  const hasDigits = isString && value.trim() !== '';
  if (hasDigits) {
    const parsed = Number(value);
    const isParsedFinite = Number.isFinite(parsed);
    if (isParsedFinite) {
      return parsed;
    }
  }

  return undefined;
}

export async function encryptFileMetadata(
  masterKey: CryptoKey,
  uid: string,
  metadata: FileMetadataPlaintext,
  bindAt = 0,
): Promise<string> {
  const metaKey = await deriveMetadataKey(masterKey, uid);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encodeBlobAad('pear-keep-meta', uid, bindAt),
      },
      metaKey,
      plaintext,
    ),
  );

  return bytesToBase64(packVersionedBlob(E2EE_BLOB_VERSION, iv, ciphertext));
}

export async function decryptFileMetadata(
  masterKey: CryptoKey,
  uid: string,
  metadataCipher: string,
  bindAt = 0,
): Promise<FileMetadataPlaintext> {
  let payload: Uint8Array;
  try {
    payload = base64ToBytes(metadataCipher);
  } catch {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  const blob = readVersionedBlob(payload, isE2eeBlobVersion);
  const isBlobMissing = blob === undefined;
  if (isBlobMissing) {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  const metaKey = await deriveMetadataKey(masterKey, uid);
  const params: AesGcmParams = { name: 'AES-GCM', iv: blob.iv };
  const isCurrentBlobVersion = blob.version === E2EE_BLOB_VERSION;
  if (isCurrentBlobVersion) {
    params.additionalData = encodeBlobAad('pear-keep-meta', uid, bindAt);
  }

  let plaintext: BufferSource;
  try {
    plaintext = await crypto.subtle.decrypt(params, metaKey, blob.ciphertext);
  } catch {
    throw cryptoError('cannotDecryptMetadata');
  }

  try {
    return parseFileMetadataPlaintext(JSON.parse(new TextDecoder().decode(plaintext)));
  } catch (error) {
    const isMetadataFormatError = isPearKeepCryptoError(error);
    if (isMetadataFormatError) {
      throw error;
    }

    throw cryptoError('invalidEncryptedMetadataFormat');
  }
}

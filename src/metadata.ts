import { cryptoError, isPearKeepCryptoError } from './errors.ts';
import {
  E2EE_BLOB_OVERHEAD,
  E2EE_BLOB_VERSION,
  E2EE_PLACEHOLDER_LABEL,
} from './constants.ts';
import { encodeBlobAad, isE2eeBlobVersion } from './blobCore.ts';
import { bytesToBase64, base64ToBytes, concatBytes } from './encoding.ts';
import { deriveMetadataKey } from './keys.ts';
import { parseFileMetadataPlaintext } from './jsonGuards.ts';

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

export async function encryptFileMetadata(
  masterKey: CryptoKey,
  uid: string,
  metadata: FileMetadataPlaintext,
  bindAt = 0,
): Promise<string> {
  const metaKey = await deriveMetadataKey(masterKey, uid);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: encodeBlobAad('pear-keep-meta', uid, bindAt),
    },
    metaKey,
    plaintext,
  ));

  const payload = concatBytes([
    new Uint8Array([E2EE_BLOB_VERSION]),
    iv,
    ciphertext,
  ]);

  return bytesToBase64(payload);
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

  const version = payload[0];
  if (version === undefined || payload.length < E2EE_BLOB_OVERHEAD || !isE2eeBlobVersion(version)) {
    throw cryptoError('invalidEncryptedMetadataFormat');
  }

  const iv = payload.slice(1, 13);
  const ciphertext = payload.slice(13);
  const metaKey = await deriveMetadataKey(masterKey, uid);
  const params: AesGcmParams = { name: 'AES-GCM', iv };
  if (version === E2EE_BLOB_VERSION) {
    params.additionalData = encodeBlobAad('pear-keep-meta', uid, bindAt);
  }

  let plaintext: BufferSource;
  try {
    plaintext = await crypto.subtle.decrypt(
      params,
      metaKey,
      ciphertext,
    );
  } catch {
    throw cryptoError('cannotDecryptMetadata');
  }

  try {
    return parseFileMetadataPlaintext(JSON.parse(new TextDecoder().decode(plaintext)));
  } catch (error) {
    if (isPearKeepCryptoError(error)) {
      throw error;
    }

    throw cryptoError('invalidEncryptedMetadataFormat');
  }
}

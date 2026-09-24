import { cryptoError } from '../errors.ts';
import { AES_GCM_IV_BYTES, E2EE_BLOB_VERSION } from '../constants.ts';
import { deriveFileKeyFromRaw } from '../keys/keyMaterial.ts';
import {
  encodeBlobAad,
  isE2eeBlobVersion,
  packVersionedBlob,
  readVersionedBlob,
} from '../wire/blobFrame.ts';

export async function encryptBytes(
  masterKeyRaw: Uint8Array,
  uid: string,
  plaintext: Uint8Array,
  bindAt = 0,
): Promise<Uint8Array> {
  const isPlaintextEmpty = plaintext.byteLength === 0;
  if (isPlaintextEmpty) {
    return plaintext;
  }

  const fileKey = await deriveFileKeyFromRaw(masterKeyRaw, uid);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encodeBlobAad('pear-keep-file', uid, bindAt),
      },
      fileKey,
      plaintext,
    ),
  );

  return packVersionedBlob(E2EE_BLOB_VERSION, iv, ciphertext);
}

export async function decryptBytes(
  masterKeyRaw: Uint8Array,
  uid: string,
  payload: Uint8Array,
  bindAt = 0,
): Promise<Uint8Array> {
  const isPayloadEmpty = payload.byteLength === 0;
  if (isPayloadEmpty) {
    return payload;
  }

  const blob = readVersionedBlob(payload, isE2eeBlobVersion);
  const isBlobMissing = blob === undefined;
  if (isBlobMissing) {
    throw cryptoError('invalidEncryptedFileFormat');
  }

  const fileKey = await deriveFileKeyFromRaw(masterKeyRaw, uid);
  const params: AesGcmParams = { name: 'AES-GCM', iv: blob.iv };
  const isCurrentBlobVersion = blob.version === E2EE_BLOB_VERSION;
  if (isCurrentBlobVersion) {
    params.additionalData = encodeBlobAad('pear-keep-file', uid, bindAt);
  }

  return new Uint8Array(await crypto.subtle.decrypt(params, fileKey, blob.ciphertext));
}

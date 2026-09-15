import { cryptoError } from './errors.ts';
import {
  E2EE_BLOB_OVERHEAD,
  E2EE_BLOB_VERSION,
  E2EE_BLOB_VERSION_LEGACY,
} from './constants.ts';
import { concatBytes } from './encoding.ts';
import { deriveFileKeyFromRaw } from './keyMaterial.ts';

export function isE2eeBlobVersion(version: number): boolean {
  return version === E2EE_BLOB_VERSION_LEGACY || version === E2EE_BLOB_VERSION;
}

export type BlobAadScope = 'pear-keep-file' | 'pear-keep-meta' | 'pear-keep-search' | 'pear-keep-settings';

export function encodeBlobAad(scope: BlobAadScope, uid: string, bindAt: number): Uint8Array {
  return new TextEncoder().encode(`${scope}:${uid}:${bindAt}`);
}

export async function encryptBytes(
  masterKeyRaw: Uint8Array,
  uid: string,
  plaintext: Uint8Array,
  bindAt = 0,
): Promise<Uint8Array> {
  if (plaintext.byteLength === 0) {
    return plaintext;
  }

  const fileKey = await deriveFileKeyFromRaw(masterKeyRaw, uid);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: encodeBlobAad('pear-keep-file', uid, bindAt),
    },
    fileKey,
    plaintext,
  ));

  return concatBytes([
    new Uint8Array([E2EE_BLOB_VERSION]),
    iv,
    ciphertext,
  ]);
}

export async function decryptBytes(
  masterKeyRaw: Uint8Array,
  uid: string,
  payload: Uint8Array,
  bindAt = 0,
): Promise<Uint8Array> {
  if (payload.byteLength === 0) {
    return payload;
  }

  const version = payload[0];
  if (version === undefined || payload.byteLength < E2EE_BLOB_OVERHEAD || !isE2eeBlobVersion(version)) {
    throw cryptoError('invalidEncryptedFileFormat');
  }

  const iv = payload.slice(1, 13);
  const ciphertext = payload.slice(13);
  const fileKey = await deriveFileKeyFromRaw(masterKeyRaw, uid);
  const params: AesGcmParams = { name: 'AES-GCM', iv };
  if (version === E2EE_BLOB_VERSION) {
    params.additionalData = encodeBlobAad('pear-keep-file', uid, bindAt);
  }

  return new Uint8Array(await crypto.subtle.decrypt(
    params,
    fileKey,
    ciphertext,
  ));
}

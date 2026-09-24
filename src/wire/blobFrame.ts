import {
  AES_GCM_IV_BYTES,
  BLOB_VERSION_BYTES,
  E2EE_BLOB_OVERHEAD,
  E2EE_BLOB_VERSION,
  E2EE_BLOB_VERSION_LEGACY,
} from '../constants.ts';
import { concatBytes } from '../encoding.ts';

export function isE2eeBlobVersion(version: number): boolean {
  const isLegacyVersion = version === E2EE_BLOB_VERSION_LEGACY;
  const isCurrentVersion = version === E2EE_BLOB_VERSION;

  return isLegacyVersion || isCurrentVersion;
}

export type BlobAadScope =
  'pear-keep-file' | 'pear-keep-meta' | 'pear-keep-search' | 'pear-keep-settings';

export function encodeBlobAad(scope: BlobAadScope, uid: string, bindAt: number): Uint8Array {
  return new TextEncoder().encode(`${scope}:${uid}:${bindAt}`);
}

export interface VersionedBlob {
  version: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

/** Split `version | iv | ciphertext`. Undefined when the frame is too short or the version is rejected. */
export function readVersionedBlob(
  payload: Uint8Array,
  acceptsVersion: (version: number) => boolean,
): VersionedBlob | undefined {
  const version = payload[0];
  const isVersionMissing = version === undefined;
  const isFrameTooShort = payload.byteLength < E2EE_BLOB_OVERHEAD;
  const isVersionRejected = !isVersionMissing && !acceptsVersion(version);
  if (isVersionMissing || isFrameTooShort || isVersionRejected) {
    return undefined;
  }

  const ciphertextOffset = BLOB_VERSION_BYTES + AES_GCM_IV_BYTES;

  return {
    version,
    iv: payload.slice(BLOB_VERSION_BYTES, ciphertextOffset),
    ciphertext: payload.slice(ciphertextOffset),
  };
}

export function packVersionedBlob(
  version: number,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return concatBytes([new Uint8Array([version]), iv, ciphertext]);
}

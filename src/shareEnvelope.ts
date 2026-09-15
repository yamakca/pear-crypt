import { cryptoError, isPearKeepCryptoError } from './errors.ts';
import {
  E2EE_BLOB_OVERHEAD,
  SHARE_BLOB_VERSION,
  SHARE_KEY_BYTES,
} from './constants.ts';
import { concatBytes } from './encoding.ts';
import { parseShareEnvelopeHeader } from './jsonGuards.ts';

export interface ShareEnvelopePayload {
  filename: string;
  mime: string;
  bytes: Uint8Array;
}

function getSubtleCrypto(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw cryptoError('webCryptoUnavailable');
  }

  return globalThis.crypto.subtle;
}

export function generateShareKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(SHARE_KEY_BYTES));
}

export function encodeShareAad(publicId: string): Uint8Array {
  return new TextEncoder().encode(`pear-keep-share:${publicId}`);
}

async function importShareKey(shareKey: Uint8Array): Promise<CryptoKey> {
  if (shareKey.byteLength !== SHARE_KEY_BYTES) {
    throw cryptoError('invalidShareKey');
  }

  return getSubtleCrypto().importKey(
    'raw',
    shareKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

function encodePlaintext(payload: ShareEnvelopePayload): Uint8Array {
  const header = new TextEncoder().encode(JSON.stringify({
    filename: payload.filename,
    mime: payload.mime || 'application/pdf',
  }));
  if (header.byteLength > 0xffff) {
    throw cryptoError('invalidShareEnvelope');
  }

  const prefix = new Uint8Array(2);
  new DataView(prefix.buffer).setUint16(0, header.byteLength, false);
  return concatBytes([prefix, header, payload.bytes]);
}

function decodePlaintext(plaintext: Uint8Array): ShareEnvelopePayload {
  if (plaintext.byteLength < 2) {
    throw cryptoError('invalidShareEnvelope');
  }

  const headerLength = new DataView(plaintext.buffer, plaintext.byteOffset, 2).getUint16(0, false);
  if (plaintext.byteLength < 2 + headerLength) {
    throw cryptoError('invalidShareEnvelope');
  }

  let header: ReturnType<typeof parseShareEnvelopeHeader>;
  try {
    header = parseShareEnvelopeHeader(JSON.parse(new TextDecoder().decode(plaintext.slice(2, 2 + headerLength))));
  } catch (error) {
    if (isPearKeepCryptoError(error)) {
      throw error;
    }

    throw cryptoError('invalidShareEnvelope');
  }

  return {
    filename: header.filename,
    mime: header.mime && header.mime.trim() !== '' ? header.mime : 'application/pdf',
    bytes: plaintext.slice(2 + headerLength),
  };
}

export async function encryptShareEnvelope(
  shareKey: Uint8Array,
  publicId: string,
  payload: ShareEnvelopePayload,
): Promise<Uint8Array> {
  const key = await importShareKey(shareKey);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await getSubtleCrypto().encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: encodeShareAad(publicId),
    },
    key,
    encodePlaintext(payload),
  ));

  return concatBytes([
    new Uint8Array([SHARE_BLOB_VERSION]),
    iv,
    ciphertext,
  ]);
}

export async function decryptShareEnvelope(
  shareKey: Uint8Array,
  publicId: string,
  payload: Uint8Array,
): Promise<ShareEnvelopePayload> {
  const version = payload[0];
  if (version === undefined || payload.byteLength < E2EE_BLOB_OVERHEAD || version !== SHARE_BLOB_VERSION) {
    throw cryptoError('invalidShareEnvelope');
  }

  const key = await importShareKey(shareKey);
  const iv = payload.slice(1, 13);
  const ciphertext = payload.slice(13);

  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(await getSubtleCrypto().decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encodeShareAad(publicId),
      },
      key,
      ciphertext,
    ));
  } catch {
    throw cryptoError('invalidShareKey');
  }

  return decodePlaintext(plaintext);
}

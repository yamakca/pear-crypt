import { cryptoError, isPearKeepCryptoError } from '../errors.ts';
import {
  AES_GCM_IV_BYTES,
  AES_GCM_KEY_BITS,
  SHARE_BLOB_VERSION,
  SHARE_KEY_BYTES,
} from '../constants.ts';
import { concatBytes } from '../encoding.ts';
import { isNonEmptyString, isRecord } from '../json.ts';
import { requireSubtleCrypto } from '../webCrypto.ts';
import { packVersionedBlob, readVersionedBlob } from '../wire/blobFrame.ts';

interface ShareEnvelopeHeaderJson {
  filename: string;
  mime?: string;
}

function parseShareEnvelopeHeader(value: unknown): ShareEnvelopeHeaderJson {
  const isHeaderObject = isRecord(value);
  if (!isHeaderObject) {
    throw cryptoError('invalidShareEnvelope');
  }

  const filename = value.filename;
  const hasFilename = isNonEmptyString(filename);
  if (!hasFilename) {
    throw cryptoError('invalidShareEnvelope');
  }

  const header: ShareEnvelopeHeaderJson = { filename };
  const mimeValue = value.mime;
  const isMimePresent = mimeValue !== undefined;
  if (isMimePresent) {
    const isMimeString = typeof mimeValue === 'string';
    if (!isMimeString) {
      throw cryptoError('invalidShareEnvelope');
    }

    header.mime = mimeValue;
  }

  return header;
}

const DEFAULT_SHARE_MIME = 'application/pdf';
const HEADER_LENGTH_BYTES = 2;
const BITS_PER_BYTE = 8;
const MAX_HEADER_BYTES = 2 ** (HEADER_LENGTH_BYTES * BITS_PER_BYTE) - 1;

export interface ShareEnvelopePayload {
  filename: string;
  mime: string;
  bytes: Uint8Array;
}

export function generateShareKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(SHARE_KEY_BYTES));
}

export function encodeShareAad(publicId: string): Uint8Array {
  return new TextEncoder().encode(`pear-keep-share:${publicId}`);
}

async function importShareKey(shareKey: Uint8Array): Promise<CryptoKey> {
  const isShareKeyLengthWrong = shareKey.byteLength !== SHARE_KEY_BYTES;
  if (isShareKeyLengthWrong) {
    throw cryptoError('invalidShareKey');
  }

  return requireSubtleCrypto('webCryptoUnavailable').importKey(
    'raw',
    shareKey,
    { name: 'AES-GCM', length: AES_GCM_KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

function encodePlaintext(payload: ShareEnvelopePayload): Uint8Array {
  const hasMime = payload.mime !== '';
  const mime = hasMime ? payload.mime : DEFAULT_SHARE_MIME;
  const header = new TextEncoder().encode(
    JSON.stringify({
      filename: payload.filename,
      mime,
    }),
  );
  const isHeaderTooLong = header.byteLength > MAX_HEADER_BYTES;
  if (isHeaderTooLong) {
    throw cryptoError('invalidShareEnvelope');
  }

  const prefix = new Uint8Array(HEADER_LENGTH_BYTES);
  new DataView(prefix.buffer).setUint16(0, header.byteLength, false);

  return concatBytes([prefix, header, payload.bytes]);
}

function decodePlaintext(plaintext: Uint8Array): ShareEnvelopePayload {
  const isShorterThanLengthPrefix = plaintext.byteLength < HEADER_LENGTH_BYTES;
  if (isShorterThanLengthPrefix) {
    throw cryptoError('invalidShareEnvelope');
  }

  const headerLength = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    HEADER_LENGTH_BYTES,
  ).getUint16(0, false);
  const bodyOffset = HEADER_LENGTH_BYTES + headerLength;
  const isShorterThanHeader = plaintext.byteLength < bodyOffset;
  if (isShorterThanHeader) {
    throw cryptoError('invalidShareEnvelope');
  }

  let header: ReturnType<typeof parseShareEnvelopeHeader>;
  try {
    const headerJson = new TextDecoder().decode(plaintext.slice(HEADER_LENGTH_BYTES, bodyOffset));
    header = parseShareEnvelopeHeader(JSON.parse(headerJson));
  } catch (error) {
    const isShareFormatError = isPearKeepCryptoError(error);
    if (isShareFormatError) {
      throw error;
    }

    throw cryptoError('invalidShareEnvelope');
  }

  const mimeValue = header.mime;
  const isMimeDefined = mimeValue !== undefined;
  let mime = DEFAULT_SHARE_MIME;
  if (isMimeDefined) {
    const isMimeBlank = mimeValue.trim() === '';
    if (!isMimeBlank) {
      mime = mimeValue;
    }
  }

  return {
    filename: header.filename,
    mime,
    bytes: plaintext.slice(bodyOffset),
  };
}

export async function encryptShareEnvelope(
  shareKey: Uint8Array,
  publicId: string,
  payload: ShareEnvelopePayload,
): Promise<Uint8Array> {
  const key = await importShareKey(shareKey);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ciphertext = new Uint8Array(
    await requireSubtleCrypto('webCryptoUnavailable').encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encodeShareAad(publicId),
      },
      key,
      encodePlaintext(payload),
    ),
  );

  return packVersionedBlob(SHARE_BLOB_VERSION, iv, ciphertext);
}

export async function decryptShareEnvelope(
  shareKey: Uint8Array,
  publicId: string,
  payload: Uint8Array,
): Promise<ShareEnvelopePayload> {
  const blob = readVersionedBlob(payload, (version) => {
    const isShareVersion = version === SHARE_BLOB_VERSION;

    return isShareVersion;
  });
  const isBlobMissing = blob === undefined;
  if (isBlobMissing) {
    throw cryptoError('invalidShareEnvelope');
  }

  const key = await importShareKey(shareKey);

  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await requireSubtleCrypto('webCryptoUnavailable').decrypt(
        {
          name: 'AES-GCM',
          iv: blob.iv,
          additionalData: encodeShareAad(publicId),
        },
        key,
        blob.ciphertext,
      ),
    );
  } catch {
    throw cryptoError('invalidShareKey');
  }

  return decodePlaintext(plaintext);
}

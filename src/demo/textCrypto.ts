import {
  AES_GCM_IV_BYTES,
  BLOB_VERSION_BYTES,
  E2EE_SALT_BYTES,
  E2EE_WRAP_PAYLOAD_VERSION_PBKDF2,
} from '../constants.ts';
import { base64ToBytes, bytesToBase64 } from '../encoding.ts';
import {
  decryptWithKey,
  derivePasswordKey,
  encryptWithKey,
  generateSalt,
} from '../keys/masterKeyCrypto.ts';

const DEMO_WIRE_PREFIX = 'pk1.';
const DEMO_WIRE_VERSION = 1;
const DEMO_MIN_DATA_BYTES = 1;

/** Opaque ciphertext. The password is not included. */
export function packDemoCiphertext(parts: {
  salt: Uint8Array;
  iv: Uint8Array;
  data: Uint8Array;
}): string {
  const isSaltLengthWrong = parts.salt.byteLength !== E2EE_SALT_BYTES;
  const isIvLengthWrong = parts.iv.byteLength !== AES_GCM_IV_BYTES;
  if (isSaltLengthWrong || isIvLengthWrong) {
    throw new Error('invalid-envelope');
  }

  const saltOffset = BLOB_VERSION_BYTES;
  const ivOffset = saltOffset + parts.salt.byteLength;
  const dataOffset = ivOffset + parts.iv.byteLength;
  const packed = new Uint8Array(dataOffset + parts.data.byteLength);
  packed[0] = DEMO_WIRE_VERSION;
  packed.set(parts.salt, saltOffset);
  packed.set(parts.iv, ivOffset);
  packed.set(parts.data, dataOffset);

  return `${DEMO_WIRE_PREFIX}${bytesToBase64(packed)}`;
}

export function unpackDemoCiphertext(raw: string): {
  salt: Uint8Array;
  iv: Uint8Array;
  data: Uint8Array;
} {
  const trimmed = raw.trim();
  const hasDemoPrefix = trimmed.startsWith(DEMO_WIRE_PREFIX);
  if (!hasDemoPrefix) {
    throw new Error('invalid-envelope');
  }

  const packed = base64ToBytes(trimmed.slice(DEMO_WIRE_PREFIX.length));
  const minLength = BLOB_VERSION_BYTES + E2EE_SALT_BYTES + AES_GCM_IV_BYTES + DEMO_MIN_DATA_BYTES;
  const isPackedTooShort = packed.byteLength < minLength;
  const isWrongDemoVersion = packed[0] !== DEMO_WIRE_VERSION;
  if (isPackedTooShort || isWrongDemoVersion) {
    throw new Error('invalid-envelope');
  }

  const saltStart = BLOB_VERSION_BYTES;
  const ivStart = saltStart + E2EE_SALT_BYTES;
  const dataStart = ivStart + AES_GCM_IV_BYTES;

  return {
    salt: packed.slice(saltStart, ivStart),
    iv: packed.slice(ivStart, dataStart),
    data: packed.slice(dataStart),
  };
}

export async function encryptDemoText(plaintext: string, password: string): Promise<string> {
  const isPasswordEmpty = password === '';
  if (isPasswordEmpty) {
    throw new Error('empty-password');
  }

  const salt = generateSalt();
  const key = await derivePasswordKey(password, salt);
  const payload = await encryptWithKey(key, new TextEncoder().encode(plaintext));

  return packDemoCiphertext({
    salt,
    iv: base64ToBytes(payload.iv),
    data: base64ToBytes(payload.data),
  });
}

export async function decryptDemoText(ciphertext: string, password: string): Promise<string> {
  const isPasswordEmpty = password === '';
  if (isPasswordEmpty) {
    throw new Error('empty-password');
  }

  const parts = unpackDemoCiphertext(ciphertext);
  const key = await derivePasswordKey(password, parts.salt);
  const plaintext = await decryptWithKey(key, {
    v: E2EE_WRAP_PAYLOAD_VERSION_PBKDF2,
    iv: bytesToBase64(parts.iv),
    data: bytesToBase64(parts.data),
  });

  return new TextDecoder().decode(plaintext);
}

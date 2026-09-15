import { E2EE_SALT_BYTES } from './constants.ts';
import { base64ToBytes, bytesToBase64 } from './encoding.ts';
import {
  decryptWithKey,
  derivePasswordKey,
  encryptWithKey,
  generateSalt,
} from './keys/masterKeyCrypto.ts';

const DEMO_WIRE_PREFIX = 'pk1.';
const DEMO_IV_BYTES = 12;

/** Opaque portable ciphertext: what a server could store without the password. */
export function packDemoCiphertext(parts: {
  salt: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
}): string {
  if (parts.salt.byteLength !== E2EE_SALT_BYTES || parts.iv.byteLength !== DEMO_IV_BYTES) {
    throw new Error('invalid-envelope');
  }

  const packed = new Uint8Array(1 + parts.salt.byteLength + parts.iv.byteLength + parts.data.byteLength);
  packed[0] = 1;
  packed.set(parts.salt, 1);
  packed.set(parts.iv, 1 + parts.salt.byteLength);
  packed.set(parts.data, 1 + parts.salt.byteLength + parts.iv.byteLength);
  return `${DEMO_WIRE_PREFIX}${bytesToBase64(packed)}`;
}

export function unpackDemoCiphertext(raw: string): {
  salt: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
} {
  const trimmed = raw.trim();
  if (!trimmed.startsWith(DEMO_WIRE_PREFIX)) {
    throw new Error('invalid-envelope');
  }

  const packed = base64ToBytes(trimmed.slice(DEMO_WIRE_PREFIX.length));
  const minLength = 1 + E2EE_SALT_BYTES + DEMO_IV_BYTES + 1;
  if (packed.byteLength < minLength || packed[0] !== 1) {
    throw new Error('invalid-envelope');
  }

  const saltStart = 1;
  const ivStart = saltStart + E2EE_SALT_BYTES;
  const dataStart = ivStart + DEMO_IV_BYTES;
  return {
    salt: packed.slice(saltStart, ivStart),
    iv: packed.slice(ivStart, dataStart),
    data: packed.slice(dataStart),
  };
}

export async function encryptDemoText(
  plaintext: string,
  password: string,
): Promise<string> {
  if (password === '') {
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

export async function decryptDemoText(
  ciphertext: string,
  password: string,
): Promise<string> {
  if (password === '') {
    throw new Error('empty-password');
  }

  const parts = unpackDemoCiphertext(ciphertext);
  const key = await derivePasswordKey(password, parts.salt);
  const plaintext = await decryptWithKey(key, {
    v: 1,
    iv: bytesToBase64(parts.iv),
    data: bytesToBase64(parts.data),
  });

  return new TextDecoder().decode(plaintext);
}

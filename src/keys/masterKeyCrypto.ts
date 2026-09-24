import { argon2id } from 'hash-wasm';
import { cryptoError } from '../errors.ts';
import { requireSubtleCrypto } from '../webCrypto.ts';
import {
  AES_GCM_IV_BYTES,
  AES_GCM_KEY_BITS,
  E2EE_ARGON2_HASH_LENGTH,
  E2EE_ARGON2_ITERATIONS,
  E2EE_ARGON2_MEMORY_KIB,
  E2EE_ARGON2_PARALLELISM,
  E2EE_MASTER_KEY_BYTES,
  E2EE_PBKDF2_ITERATIONS,
  E2EE_SALT_BYTES,
  E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID,
  E2EE_WRAP_PAYLOAD_VERSION_PBKDF2,
} from '../constants.ts';
import { base64ToBytes, bytesToBase64 } from '../encoding.ts';
import type { WrappedMasterKeyPayload, WrapKdfParams } from './types.ts';

export function getSubtleCrypto(): SubtleCrypto {
  return requireSubtleCrypto('webCryptoUnavailableBrowser');
}

export function generateSalt(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(E2EE_SALT_BYTES));
}

export function defaultArgon2KdfParams(): WrapKdfParams {
  return {
    alg: 'argon2id',
    m: E2EE_ARGON2_MEMORY_KIB,
    t: E2EE_ARGON2_ITERATIONS,
    p: E2EE_ARGON2_PARALLELISM,
  };
}

async function importAesGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  return getSubtleCrypto().importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: AES_GCM_KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Legacy wrap derivation (payload v1). */
export async function derivePasswordKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const passwordKey = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: E2EE_PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: AES_GCM_KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function deriveArgon2idKey(
  password: string,
  salt: Uint8Array,
  params: WrapKdfParams = defaultArgon2KdfParams(),
): Promise<CryptoKey> {
  const hash = await argon2id({
    password,
    salt,
    iterations: params.t,
    memorySize: params.m,
    parallelism: params.p,
    hashLength: E2EE_ARGON2_HASH_LENGTH,
    outputType: 'binary',
  });

  return importAesGcmKey(hash);
}

export async function deriveWrapKey(
  password: string,
  salt: Uint8Array,
  payload: Pick<WrappedMasterKeyPayload, 'v' | 'kdf'>,
): Promise<CryptoKey> {
  const isArgon2idWrap = payload.v === E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID;
  if (isArgon2idWrap) {
    const hasArgon2idParams = payload.kdf?.alg === 'argon2id';
    const params =
      hasArgon2idParams && payload.kdf !== undefined ? payload.kdf : defaultArgon2KdfParams();

    return deriveArgon2idKey(password, salt, params);
  }

  return derivePasswordKey(password, salt);
}

export async function generateMasterKey(): Promise<CryptoKey> {
  return getSubtleCrypto().generateKey({ name: 'AES-GCM', length: AES_GCM_KEY_BITS }, true, [
    'encrypt',
    'decrypt',
  ]);
}

export async function exportMasterKeyRaw(masterKey: CryptoKey): Promise<Uint8Array> {
  const raw = await getSubtleCrypto().exportKey('raw', masterKey);

  return new Uint8Array(raw);
}

export async function importMasterKeyRaw(raw: Uint8Array): Promise<CryptoKey> {
  const isMasterKeyLengthWrong = raw.byteLength !== E2EE_MASTER_KEY_BYTES;
  if (isMasterKeyLengthWrong) {
    throw cryptoError('invalidMasterKey');
  }

  return getSubtleCrypto().importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: AES_GCM_KEY_BITS },
    true,
    ['encrypt', 'decrypt'],
  );
}

async function sealWithKey(
  key: CryptoKey,
  plaintext: Uint8Array,
  version: number,
  kdf?: WrapKdfParams,
): Promise<WrappedMasterKeyPayload> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ciphertext = await getSubtleCrypto().encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  const payload: WrappedMasterKeyPayload = {
    v: version,
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(ciphertext)),
  };

  const hasKdf = kdf !== undefined;
  if (hasKdf) {
    payload.kdf = kdf;
  }

  return payload;
}

export async function encryptWithKey(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<WrappedMasterKeyPayload> {
  return sealWithKey(key, plaintext, E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID, defaultArgon2KdfParams());
}

/** Encrypt with an already-derived key and force legacy PBKDF2 payload shape (tests / migration helpers). */
export async function encryptWithKeyLegacy(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<WrappedMasterKeyPayload> {
  return sealWithKey(key, plaintext, E2EE_WRAP_PAYLOAD_VERSION_PBKDF2);
}

export async function decryptWithKey(
  key: CryptoKey,
  payload: WrappedMasterKeyPayload,
): Promise<Uint8Array> {
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.data);
  const plaintext = await getSubtleCrypto().decrypt({ name: 'AES-GCM', iv }, key, ciphertext);

  return new Uint8Array(plaintext);
}

export function isLegacyWrapPayload(payload: WrappedMasterKeyPayload): boolean {
  const isArgon2idWrap = payload.v === E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID;

  return !isArgon2idWrap;
}

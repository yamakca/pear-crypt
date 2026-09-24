import { describe, expect, it } from 'vitest';
import {
  AES_GCM_IV_BYTES,
  E2EE_BLOB_OVERHEAD,
  E2EE_BLOB_VERSION,
  E2EE_BLOB_VERSION_LEGACY,
  E2EE_MASTER_KEY_BYTES,
} from './constants.ts';
import { PearKeepCryptoError } from './errors.ts';
import { decryptBytes, encryptBytes } from './files/blob.ts';
import { concatBytes } from './encoding.ts';
import { createE2eeSetup } from './keys/e2eeSetup.ts';
import { deriveFileKeyFromRaw } from './keys/keyMaterial.ts';

describe('blobCore', () => {
  it('returns empty buffers unchanged', async () => {
    const empty = new Uint8Array();
    await expect(encryptBytes(new Uint8Array(E2EE_MASTER_KEY_BYTES), 'uid', empty)).resolves.toBe(
      empty,
    );
    await expect(decryptBytes(new Uint8Array(E2EE_MASTER_KEY_BYTES), 'uid', empty)).resolves.toBe(
      empty,
    );
  });

  it('rejects invalid encrypted payloads', async () => {
    const { masterKey } = await createE2eeSetup('password');
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', masterKey));

    await expect(decryptBytes(raw, 'uid', new Uint8Array([9, 9, 9]))).rejects.toMatchObject({
      code: 'invalidEncryptedFileFormat',
    });
  });

  it('binds ciphertext to uid and content generation', async () => {
    const { masterKey } = await createE2eeSetup('password');
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', masterKey));
    const plaintext = new TextEncoder().encode('secret-body');
    const encrypted = await encryptBytes(raw, 'file-1', plaintext, 100);

    expect(encrypted[0]).toBe(E2EE_BLOB_VERSION);
    expect(new TextDecoder().decode(await decryptBytes(raw, 'file-1', encrypted, 100))).toBe(
      'secret-body',
    );
    await expect(decryptBytes(raw, 'file-1', encrypted, 99)).rejects.toThrow();
    await expect(decryptBytes(raw, 'other-uid', encrypted, 100)).rejects.toThrow();
  });

  it('still decrypts legacy blobs without AAD', async () => {
    const { masterKey } = await createE2eeSetup('password');
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', masterKey));
    const plaintext = new TextEncoder().encode('legacy');
    const fileKey = await deriveFileKeyFromRaw(raw, 'file-1');
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, plaintext),
    );
    const payload = concatBytes([new Uint8Array([E2EE_BLOB_VERSION_LEGACY]), iv, ciphertext]);

    expect(new TextDecoder().decode(await decryptBytes(raw, 'file-1', payload, 999))).toBe(
      'legacy',
    );
  });

  it('rejects a short frame and an unknown version at the overhead boundary', async () => {
    const raw = new Uint8Array(E2EE_MASTER_KEY_BYTES);
    const oneByteShort = new Uint8Array(E2EE_BLOB_OVERHEAD - 1);
    oneByteShort[0] = E2EE_BLOB_VERSION;

    await expect(decryptBytes(raw, 'uid', oneByteShort)).rejects.toMatchObject({
      code: 'invalidEncryptedFileFormat',
    });

    for (const version of [0, 3]) {
      const frame = new Uint8Array(E2EE_BLOB_OVERHEAD);
      frame[0] = version;
      await expect(decryptBytes(raw, 'uid', frame)).rejects.toMatchObject({
        code: 'invalidEncryptedFileFormat',
      });
    }
  });

  it('lets an authentication failure escape as a WebCrypto error', async () => {
    const raw = new Uint8Array(E2EE_MASTER_KEY_BYTES);
    const plaintext = new Uint8Array([1]);
    const encrypted = await encryptBytes(raw, 'file-1', plaintext, 7);
    const tampered = new Uint8Array(encrypted);
    tampered[tampered.byteLength - 1] ^= 0xff;

    await expect(decryptBytes(raw, 'file-1', tampered, 7)).rejects.not.toBeInstanceOf(
      PearKeepCryptoError,
    );

    const exactOverhead = new Uint8Array(E2EE_BLOB_OVERHEAD);
    exactOverhead[0] = E2EE_BLOB_VERSION;
    await expect(decryptBytes(raw, 'file-1', exactOverhead, 7)).rejects.not.toBeInstanceOf(
      PearKeepCryptoError,
    );

    for (const length of [0, 31, 33]) {
      await expect(encryptBytes(new Uint8Array(length), 'file-1', plaintext)).rejects.toMatchObject(
        { code: 'invalidMasterKey' },
      );
      await expect(
        decryptBytes(new Uint8Array(length), 'file-1', encrypted, 7),
      ).rejects.toMatchObject({ code: 'invalidMasterKey' });
    }
  });
});

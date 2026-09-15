import { describe, expect, it } from 'vitest';
import { decryptBytes, encryptBytes } from './blobCore.ts';
import { concatBytes } from './encoding.ts';
import { createE2eeSetup } from './keys/e2eeSetup.ts';
import { deriveFileKeyFromRaw } from './keyMaterial.ts';

describe('blobCore', () => {
  it('returns empty buffers unchanged', async () => {
    const empty = new Uint8Array();
    await expect(encryptBytes(new Uint8Array(32), 'uid', empty)).resolves.toBe(empty);
    await expect(decryptBytes(new Uint8Array(32), 'uid', empty)).resolves.toBe(empty);
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

    expect(encrypted[0]).toBe(2);
    expect(new TextDecoder().decode(await decryptBytes(raw, 'file-1', encrypted, 100))).toBe('secret-body');
    await expect(decryptBytes(raw, 'file-1', encrypted, 99)).rejects.toThrow();
    await expect(decryptBytes(raw, 'other-uid', encrypted, 100)).rejects.toThrow();
  });

  it('still decrypts legacy blobs without AAD', async () => {
    const { masterKey } = await createE2eeSetup('password');
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', masterKey));
    const plaintext = new TextEncoder().encode('legacy');
    const fileKey = await deriveFileKeyFromRaw(raw, 'file-1');
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      fileKey,
      plaintext,
    ));
    const payload = concatBytes([new Uint8Array([1]), iv, ciphertext]);

    expect(new TextDecoder().decode(await decryptBytes(raw, 'file-1', payload, 999))).toBe('legacy');
  });
});

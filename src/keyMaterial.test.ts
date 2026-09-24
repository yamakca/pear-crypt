import { describe, expect, it } from 'vitest';
import { E2EE_MASTER_KEY_BYTES } from './constants.ts';
import { createE2eeSetup } from './keys/e2eeSetup.ts';
import { exportMasterKeyRaw } from './keys/masterKeyCrypto.ts';
import {
  deriveFileKeyFromRaw,
  deriveMetadataKeyFromRaw,
  deriveSettingsKeyFromRaw,
} from './keys/keyMaterial.ts';

describe('keyMaterial', () => {
  it('derives distinct scoped keys from the master key', async () => {
    const { masterKey } = await createE2eeSetup('password');
    const raw = await exportMasterKeyRaw(masterKey);

    const fileKey = await deriveFileKeyFromRaw(raw, 'file-1');
    const metaKey = await deriveMetadataKeyFromRaw(raw, 'file-1');

    expect(fileKey.type).toBe('secret');
    expect(metaKey.type).toBe('secret');
    expect(fileKey.algorithm.name).toBe('AES-GCM');
    expect(metaKey.algorithm.name).toBe('AES-GCM');

    const settingsKey = await deriveSettingsKeyFromRaw(raw);
    expect(settingsKey.algorithm.name).toBe('AES-GCM');
  });

  it('rejects invalid master key length', async () => {
    await expect(deriveFileKeyFromRaw(new Uint8Array(8), 'uid')).rejects.toMatchObject({
      code: 'invalidMasterKey',
    });
  });

  it('requires Web Crypto', async () => {
    const subtle = globalThis.crypto.subtle;
    Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });

    await expect(
      deriveFileKeyFromRaw(new Uint8Array(E2EE_MASTER_KEY_BYTES), 'uid'),
    ).rejects.toMatchObject({
      code: 'webCryptoUnavailable',
    });

    Object.defineProperty(globalThis.crypto, 'subtle', { value: subtle, configurable: true });
  });
});

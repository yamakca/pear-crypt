import { describe, expect, it, vi } from 'vitest';
import { bytesToBase64 } from './encoding.ts';
import {
  createE2eeSetup,
  createRecoveryWrap,
  deriveFileKey,
  deriveMetadataKey,
  derivePasswordKey,
  encryptWithKeyLegacy,
  exportMasterKeyRaw,
  generateMasterKey,
  generateSalt,
  importMasterKeyRaw,
  parseWrappedMasterKeyPayload,
  rewrapMasterKey,
  unwrapMasterKey,
  unwrapMasterKeyWithRecovery,
  wrapMasterKey,
  wrappedMasterKeyNeedsKdfUpgrade,
} from './keys.ts';
import { decryptFileMetadata, encryptFileMetadata } from './metadata.ts';
import { normalizeRecoveryCode } from './recovery.ts';

describe('keys and metadata', () => {
  it('encrypts and decrypts file metadata', async () => {
    const { masterKey } = await createE2eeSetup('password-123');
    const uid = 'meta-uid';
    const cipher = await encryptFileMetadata(masterKey, uid, {
      label: 'Secret name',
      tags: 'work',
      comments: 'note',
      extension: 'pdf',
      type: 'application/pdf',
    });

    const decrypted = await decryptFileMetadata(masterKey, uid, cipher);
    expect(decrypted.label).toBe('Secret name');
    expect(decrypted.tags).toBe('work');

    await expect(decryptFileMetadata(masterKey, uid, cipher, 99)).rejects.toThrow();
  });

  it('unwraps master key with recovery code', async () => {
    const { masterKey, material, recoveryCode } = await createE2eeSetup('password-123');

    expect(material.recoveryWrappedMasterKey).toBeTruthy();
    expect(normalizeRecoveryCode(recoveryCode).length).toBeGreaterThan(10);

    const unlocked = await unwrapMasterKeyWithRecovery(
      recoveryCode,
      material.recoveryWrappedMasterKey!,
    );

    const fromPassword = await crypto.subtle.exportKey('raw', masterKey);
    const fromRecovery = await crypto.subtle.exportKey('raw', unlocked);
    expect(new Uint8Array(fromPassword)).toEqual(new Uint8Array(fromRecovery));
  });

  it('rejects wrong password when unwrapping master key', async () => {
    const { material } = await createE2eeSetup('correct-password');

    await expect(unwrapMasterKey('wrong-password', material)).rejects.toMatchObject({
      code: 'wrongPassword',
    });
  });

  it('rejects corrupt wrapped master key payloads', async () => {
    const { material } = await createE2eeSetup('password-123');

    await expect(unwrapMasterKey('password-123', {
      ...material,
      wrappedMasterKey: '{"v":1}',
    })).rejects.toMatchObject({ code: 'corruptServerE2eeData' });
  });

  it('rejects invalid master key imports', async () => {
    await expect(importMasterKeyRaw(new Uint8Array(4))).rejects.toMatchObject({
      code: 'invalidMasterKey',
    });
  });

  it('rewraps the master key with a new password', async () => {
    const { masterKey, material } = await createE2eeSetup('old-password');
    const rewrapped = await rewrapMasterKey(masterKey, 'new-password', material.keySalt);
    const unlocked = await unwrapMasterKey('new-password', {
      ...material,
      wrappedMasterKey: rewrapped,
    });

    const original = await crypto.subtle.exportKey('raw', masterKey);
    const recovered = await crypto.subtle.exportKey('raw', unlocked);
    expect(new Uint8Array(recovered)).toEqual(new Uint8Array(original));
  });

  it('unwraps legacy PBKDF2 wraps and emits Argon2id wraps for new material', async () => {
    const salt = generateSalt();
    const masterKey = await generateMasterKey();
    const passwordKey = await derivePasswordKey('legacy-pin-123456', salt);
    const raw = await exportMasterKeyRaw(masterKey);
    const legacyWrapped = JSON.stringify(await encryptWithKeyLegacy(passwordKey, raw));

    expect(wrappedMasterKeyNeedsKdfUpgrade(legacyWrapped)).toBe(true);

    const unlocked = await unwrapMasterKey('legacy-pin-123456', {
      keySalt: bytesToBase64(salt),
      wrappedMasterKey: legacyWrapped,
      keyVersion: 2,
    });
    const original = await crypto.subtle.exportKey('raw', masterKey);
    const recovered = await crypto.subtle.exportKey('raw', unlocked);
    expect(new Uint8Array(recovered)).toEqual(new Uint8Array(original));

    const modern = await wrapMasterKey(masterKey, 'modern-pin-123456', salt);
    const modernPayload = parseWrappedMasterKeyPayload(JSON.parse(modern.wrappedMasterKey));
    expect(modernPayload.v).toBe(2);
    expect(modernPayload.kdf?.alg).toBe('argon2id');
    expect(wrappedMasterKeyNeedsKdfUpgrade(modern.wrappedMasterKey)).toBe(false);
  });

  it('creates standalone recovery wrap for existing vault', async () => {
    const masterKey = await generateMasterKey();
    const first = await createRecoveryWrap(masterKey);
    const second = await createRecoveryWrap(masterKey);

    expect(first.recoveryCode).not.toBe(second.recoveryCode);

    const unlocked = await unwrapMasterKeyWithRecovery(
      first.recoveryCode,
      first.recoveryWrappedMasterKey,
    );

    const original = await crypto.subtle.exportKey('raw', masterKey);
    const recovered = await crypto.subtle.exportKey('raw', unlocked);
    expect(new Uint8Array(original)).toEqual(new Uint8Array(recovered));
  });

  it('derives scoped keys from the master key', async () => {
    const { masterKey } = await createE2eeSetup('password-123');
    const fileKey = await deriveFileKey(masterKey, 'uid-1');
    const metaKey = await deriveMetadataKey(masterKey, 'uid-1');

    expect(fileKey.type).toBe('secret');
    expect(metaKey.type).toBe('secret');
  });

  it('requires Web Crypto in keys module', async () => {
    vi.resetModules();
    const subtle = globalThis.crypto.subtle;
    Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });

    const pkg = await import('./keys/masterKeyCrypto.ts');
    await expect(pkg.generateMasterKey()).rejects.toMatchObject({
      code: 'webCryptoUnavailableBrowser',
    });

    Object.defineProperty(globalThis.crypto, 'subtle', { value: subtle, configurable: true });
  });
});

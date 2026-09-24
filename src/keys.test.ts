import { describe, expect, it, vi } from 'vitest';
import {
  AES_GCM_IV_BYTES,
  E2EE_BLOB_VERSION,
  E2EE_BLOB_VERSION_LEGACY,
  E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID,
} from './constants.ts';
import { bytesToBase64 } from './encoding.ts';
import {
  createE2eeSetup,
  createRecoveryWrap,
  deriveFileKey,
  deriveMetadataKey,
  deriveSettingsKey,
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
} from './keys/index.ts';
import { decryptFileMetadata, encryptFileMetadata } from './metadata/metadata.ts';
import { normalizeRecoveryCode } from './recovery/code.ts';

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

    await expect(decryptFileMetadata(masterKey, uid, cipher, 99)).rejects.toMatchObject({
      code: 'cannotDecryptMetadata',
    });
  });

  it('accepts legacy metadata plaintext with JSON null optional fields', async () => {
    const { masterKey } = await createE2eeSetup('password-123');
    const uid = 'meta-nulls';
    const { encodeBlobAad } = await import('./wire/blobFrame.ts');
    const { bytesToBase64, concatBytes } = await import('./encoding.ts');
    const metaKey = await deriveMetadataKey(masterKey, uid);
    const iv = new Uint8Array(AES_GCM_IV_BYTES);
    const plaintext = new TextEncoder().encode(
      JSON.stringify({
        label: 'No extension',
        tags: null,
        comments: null,
        extension: null,
        marker: null,
        type: 'application/octet-stream',
        contentUpdatedAt: null,
        contentDigest: null,
      }),
    );
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: encodeBlobAad('pear-keep-meta', uid, 0),
        },
        metaKey,
        plaintext,
      ),
    );
    const cipher = bytesToBase64(
      concatBytes([new Uint8Array([E2EE_BLOB_VERSION]), iv, ciphertext]),
    );

    await expect(decryptFileMetadata(masterKey, uid, cipher)).resolves.toEqual({
      label: 'No extension',
      type: 'application/octet-stream',
    });
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

    await expect(
      unwrapMasterKey('password-123', {
        ...material,
        wrappedMasterKey: '{"v":1}',
      }),
    ).rejects.toMatchObject({ code: 'corruptServerE2eeData' });
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
    expect(modernPayload.v).toBe(E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID);
    expect(modernPayload.kdf?.alg).toBe('argon2id');
    expect(wrappedMasterKeyNeedsKdfUpgrade(modern.wrappedMasterKey)).toBe(false);
  });

  it('creates a standalone recovery wrap for an existing master key', async () => {
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
    const settingsKey = await deriveSettingsKey(masterKey);

    expect(fileKey.type).toBe('secret');
    expect(metaKey.type).toBe('secret');
    expect(settingsKey.type).toBe('secret');
  });

  it('rejects empty or unreadable wrapped key material', async () => {
    const { material } = await createE2eeSetup('password-123');

    await expect(
      unwrapMasterKey('password-123', {
        ...material,
        wrappedMasterKey: '   ',
      }),
    ).rejects.toMatchObject({ code: 'corruptServerE2eeData' });

    await expect(
      unwrapMasterKey('password-123', {
        ...material,
        keySalt: '   ',
      }),
    ).rejects.toMatchObject({ code: 'corruptServerE2eeData' });

    await expect(
      unwrapMasterKey('password-123', {
        ...material,
        wrappedMasterKey: 'not-json',
      }),
    ).rejects.toMatchObject({ code: 'corruptServerE2eeData' });

    await expect(
      unwrapMasterKey('password-123', {
        ...material,
        keySalt: '@@@',
      }),
    ).rejects.toMatchObject({ code: 'corruptServerE2eeData' });

    expect(wrappedMasterKeyNeedsKdfUpgrade('not-json')).toBe(false);
    expect(wrappedMasterKeyNeedsKdfUpgrade('')).toBe(false);
  });

  it('rejects a bad recovery envelope and a wrong recovery code', async () => {
    const { material, recoveryCode } = await createE2eeSetup('password-123');

    await expect(unwrapMasterKeyWithRecovery(recoveryCode, '   ')).rejects.toMatchObject({
      code: 'corruptRecoveryData',
    });
    await expect(unwrapMasterKeyWithRecovery(recoveryCode, 'not-json')).rejects.toMatchObject({
      code: 'corruptRecoveryData',
    });
    await expect(unwrapMasterKeyWithRecovery(recoveryCode, '{"salt":""}')).rejects.toMatchObject({
      code: 'corruptRecoveryData',
    });
    await expect(
      unwrapMasterKeyWithRecovery('WRONG-CODE', material.recoveryWrappedMasterKey!),
    ).rejects.toMatchObject({
      code: 'invalidRecoveryCode',
    });
    await expect(
      unwrapMasterKeyWithRecovery(
        recoveryCode,
        JSON.stringify({
          salt: material.keySalt,
          wrapped: 'not-json',
        }),
      ),
    ).rejects.toMatchObject({ code: 'invalidRecoveryCode' });
  });

  it('rejects metadata that is not a blob or not JSON', async () => {
    const { masterKey } = await createE2eeSetup('password-123');

    await expect(decryptFileMetadata(masterKey, 'uid', '@@@')).rejects.toMatchObject({
      code: 'invalidEncryptedMetadataFormat',
    });
    await expect(
      decryptFileMetadata(masterKey, 'uid', bytesToBase64(new Uint8Array([2, 1, 2]))),
    ).rejects.toMatchObject({
      code: 'invalidEncryptedMetadataFormat',
    });

    const { encodeBlobAad } = await import('./wire/blobFrame.ts');
    const { concatBytes } = await import('./encoding.ts');
    const metaKey = await deriveMetadataKey(masterKey, 'uid');
    const iv = new Uint8Array(AES_GCM_IV_BYTES);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: encodeBlobAad('pear-keep-meta', 'uid', 0) },
        metaKey,
        new TextEncoder().encode('not-json'),
      ),
    );
    const cipher = bytesToBase64(
      concatBytes([new Uint8Array([E2EE_BLOB_VERSION]), iv, ciphertext]),
    );

    await expect(decryptFileMetadata(masterKey, 'uid', cipher)).rejects.toMatchObject({
      code: 'invalidEncryptedMetadataFormat',
    });

    const missingLabel = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: encodeBlobAad('pear-keep-meta', 'uid', 0) },
        metaKey,
        new TextEncoder().encode('{"label":1}'),
      ),
    );
    const missingLabelCipher = bytesToBase64(
      concatBytes([new Uint8Array([E2EE_BLOB_VERSION]), iv, missingLabel]),
    );
    await expect(decryptFileMetadata(masterKey, 'uid', missingLabelCipher)).rejects.toMatchObject({
      code: 'invalidEncryptedMetadataFormat',
    });

    const legacy = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        metaKey,
        new TextEncoder().encode('{"label":"legacy"}'),
      ),
    );
    const legacyCipher = bytesToBase64(
      concatBytes([new Uint8Array([E2EE_BLOB_VERSION_LEGACY]), iv, legacy]),
    );
    await expect(decryptFileMetadata(masterKey, 'uid', legacyCipher)).resolves.toEqual({
      label: 'legacy',
    });
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

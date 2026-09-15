import {
  encryptBytes,
  decryptBytes,
  bytesToBase64,
  bytesToBase64Url,
  base64ToBytes,
  base64UrlToBytes,
  encryptFileMetadata,
  decryptFileMetadata,
  importMasterKeyRaw,
  derivePasswordKey,
  deriveArgon2idKey,
  encryptWithKey,
  encryptWithKeyLegacy,
  decryptWithKey,
  exportMasterKeyRaw,
  unwrapMasterKey,
  wrapMasterKey,
  encryptShareEnvelope,
  decryptShareEnvelope,
  encryptDemoText,
  decryptDemoText,
  packDemoCiphertext,
  unpackDemoCiphertext,
  normalizeRecoveryCode,
  E2EE_WRAP_VERSION_VAULT,
  parseWrappedMasterKeyPayload,
} from '../index.ts';
import {
  VECTOR_SPEC_VERSION,
  FIXTURE_MASTER_KEY_HEX,
  FIXTURE_WRAP_SALT_HEX,
  FIXTURE_IV_HEX,
  FIXTURE_SHARE_KEY_HEX,
  FIXTURE_FILE_UID,
  FIXTURE_META_UID,
  FIXTURE_SHARE_PUBLIC_ID,
  FIXTURE_WRAP_PASSWORD,
  FIXTURE_DEMO_PASSWORD,
  FIXTURE_DEMO_PLAINTEXT,
  FIXTURE_FILE_PLAINTEXT_UTF8,
  FIXTURE_BIND_AT,
  FIXTURE_RECOVERY_CODE,
  hexToBytes,
  bytesToHex,
  withFixedRandom,
} from './cryptoVectorFixtures.ts';
import type { CryptoVectorsDocument } from './cryptoVectorsTypes.ts';

export type { CryptoVectorsDocument } from './cryptoVectorsTypes.ts';

export async function buildCryptoVectorsDocument(): Promise<CryptoVectorsDocument> {
  const masterKeyRaw = hexToBytes(FIXTURE_MASTER_KEY_HEX);
  const masterKey = await importMasterKeyRaw(masterKeyRaw);
  const wrapSalt = hexToBytes(FIXTURE_WRAP_SALT_HEX);
  const fixedIv = hexToBytes(FIXTURE_IV_HEX);
  const shareKey = hexToBytes(FIXTURE_SHARE_KEY_HEX);
  const filePlaintext = new TextEncoder().encode(FIXTURE_FILE_PLAINTEXT_UTF8);

  const encodingInput = new Uint8Array([0, 1, 2, 250, 255]);
  const encodingBase64 = bytesToBase64(encodingInput);
  const encodingBase64Url = bytesToBase64Url(shareKey);

  const fileBlobCipher = await withFixedRandom([fixedIv], () =>
    encryptBytes(masterKeyRaw, FIXTURE_FILE_UID, filePlaintext, FIXTURE_BIND_AT),
  );
  const fileBlobDecrypted = await decryptBytes(
    masterKeyRaw,
    FIXTURE_FILE_UID,
    fileBlobCipher,
    FIXTURE_BIND_AT,
  );

  const metadataCipher = await withFixedRandom([fixedIv], () =>
    encryptFileMetadata(masterKey, FIXTURE_META_UID, {
      label: 'Secret name',
      tags: 'work',
      extension: 'pdf',
      type: 'application/pdf',
    }, FIXTURE_BIND_AT),
  );
  const metadataDecrypted = await decryptFileMetadata(
    masterKey,
    FIXTURE_META_UID,
    metadataCipher,
    FIXTURE_BIND_AT,
  );

  const sharePdfBytes = new TextEncoder().encode('%PDF-1.4 vector');
  const shareBlob = await withFixedRandom([fixedIv], () =>
    encryptShareEnvelope(shareKey, FIXTURE_SHARE_PUBLIC_ID, {
      filename: 'vector.pdf',
      mime: 'application/pdf',
      bytes: sharePdfBytes,
    }),
  );
  const shareDecrypted = await decryptShareEnvelope(
    shareKey,
    FIXTURE_SHARE_PUBLIC_ID,
    shareBlob,
  );

  const pbkdf2WrapKey = await derivePasswordKey(FIXTURE_WRAP_PASSWORD, wrapSalt);
  const pbkdf2Payload = await withFixedRandom([fixedIv], () =>
    encryptWithKeyLegacy(pbkdf2WrapKey, masterKeyRaw),
  );
  const pbkdf2Unwrapped = await decryptWithKey(pbkdf2WrapKey, pbkdf2Payload);

  const argon2WrapKey = await deriveArgon2idKey(FIXTURE_WRAP_PASSWORD, wrapSalt);
  const argon2Payload = await withFixedRandom([fixedIv], () =>
    encryptWithKey(argon2WrapKey, masterKeyRaw),
  );
  const argon2Unwrapped = await decryptWithKey(argon2WrapKey, argon2Payload);

  const modernWrap = await withFixedRandom([wrapSalt, fixedIv], async () =>
    wrapMasterKey(masterKey, FIXTURE_WRAP_PASSWORD, wrapSalt),
  );
  const modernUnlocked = await unwrapMasterKey(FIXTURE_WRAP_PASSWORD, {
    keySalt: modernWrap.keySalt,
    wrappedMasterKey: modernWrap.wrappedMasterKey,
    keyVersion: E2EE_WRAP_VERSION_VAULT,
  });
  const modernUnlockedRaw = await exportMasterKeyRaw(modernUnlocked);

  const demoCiphertext = await withFixedRandom([wrapSalt, fixedIv], () =>
    encryptDemoText(FIXTURE_DEMO_PLAINTEXT, FIXTURE_DEMO_PASSWORD),
  );
  const demoDecrypted = await decryptDemoText(demoCiphertext, FIXTURE_DEMO_PASSWORD);
  const demoParts = unpackDemoCiphertext(demoCiphertext);
  const demoRepacked = packDemoCiphertext(demoParts);

  return {
    specVersion: VECTOR_SPEC_VERSION,
    productVersion: '0.9.3',
    description: 'Deterministic pear-crypt test vectors. All secrets are synthetic.',
    fixtures: {
      masterKeyHex: FIXTURE_MASTER_KEY_HEX,
      wrapSaltHex: FIXTURE_WRAP_SALT_HEX,
      ivHex: FIXTURE_IV_HEX,
      shareKeyHex: FIXTURE_SHARE_KEY_HEX,
      fileUid: FIXTURE_FILE_UID,
      metaUid: FIXTURE_META_UID,
      sharePublicId: FIXTURE_SHARE_PUBLIC_ID,
      wrapPassword: FIXTURE_WRAP_PASSWORD,
      demoPassword: FIXTURE_DEMO_PASSWORD,
      bindAt: FIXTURE_BIND_AT,
      recoveryCode: FIXTURE_RECOVERY_CODE,
      recoveryCodeNormalized: normalizeRecoveryCode(FIXTURE_RECOVERY_CODE),
    },
    vectors: {
      encoding: {
        base64: {
          inputHex: bytesToHex(encodingInput),
          output: encodingBase64,
        },
        base64Url: {
          inputHex: FIXTURE_SHARE_KEY_HEX,
          output: encodingBase64Url,
          roundtripHex: bytesToHex(base64UrlToBytes(encodingBase64Url)),
        },
        base64Roundtrip: {
          inputHex: bytesToHex(base64ToBytes(encodingBase64)),
        },
      },
      fileBlob: {
        plaintextUtf8: FIXTURE_FILE_PLAINTEXT_UTF8,
        bindAt: FIXTURE_BIND_AT,
        ciphertextHex: bytesToHex(fileBlobCipher),
        decryptedUtf8: new TextDecoder().decode(fileBlobDecrypted),
      },
      metadata: {
        plaintext: {
          label: 'Secret name',
          tags: 'work',
          extension: 'pdf',
          type: 'application/pdf',
        },
        bindAt: FIXTURE_BIND_AT,
        ciphertextBase64: metadataCipher,
        decrypted: metadataDecrypted,
      },
      shareEnvelope: {
        filename: 'vector.pdf',
        mime: 'application/pdf',
        plaintextHex: bytesToHex(sharePdfBytes),
        shareUrlFragment: `#k=${encodingBase64Url}`,
        ciphertextHex: bytesToHex(shareBlob),
        decrypted: {
          filename: shareDecrypted.filename,
          mime: shareDecrypted.mime,
          plaintextHex: bytesToHex(shareDecrypted.bytes),
        },
      },
      masterKeyWrap: {
        pbkdf2Legacy: {
          password: FIXTURE_WRAP_PASSWORD,
          saltBase64: bytesToBase64(wrapSalt),
          payload: pbkdf2Payload,
          unwrappedMasterKeyHex: bytesToHex(pbkdf2Unwrapped),
        },
        argon2idModern: {
          password: FIXTURE_WRAP_PASSWORD,
          saltBase64: bytesToBase64(wrapSalt),
          payload: argon2Payload,
          unwrappedMasterKeyHex: bytesToHex(argon2Unwrapped),
        },
        fullWrapRoundtrip: {
          keySalt: modernWrap.keySalt,
          wrappedMasterKey: parseWrappedMasterKeyPayload(JSON.parse(modernWrap.wrappedMasterKey)),
          unwrappedMasterKeyHex: bytesToHex(modernUnlockedRaw),
        },
      },
      demoSandbox: {
        plaintext: FIXTURE_DEMO_PLAINTEXT,
        password: FIXTURE_DEMO_PASSWORD,
        wirePrefix: 'pk1.',
        ciphertext: demoCiphertext,
        decrypted: demoDecrypted,
        repackedCiphertext: demoRepacked,
        unpacked: {
          saltHex: bytesToHex(demoParts.salt),
          ivHex: bytesToHex(demoParts.iv),
          dataHex: bytesToHex(demoParts.data),
        },
      },
      recoveryCode: {
        input: FIXTURE_RECOVERY_CODE,
        normalized: normalizeRecoveryCode(FIXTURE_RECOVERY_CODE),
      },
    },
  };
}

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  decryptBytes,
  decryptDemoText,
  decryptFileMetadata,
  decryptShareEnvelope,
  decryptWithKey,
  deriveArgon2idKey,
  derivePasswordKey,
  E2EE_WRAP_VERSION_VAULT,
  exportMasterKeyRaw,
  importMasterKeyRaw,
  unpackDemoCiphertext,
  unwrapMasterKey,
} from './index.ts';
import { buildCryptoVectorsDocument } from './test/buildCryptoVectorsDocument.ts';
import type { CryptoVectorsDocument } from './test/cryptoVectorsTypes.ts';
import { parseCryptoVectorsDocument } from './test/cryptoVectorsTypes.ts';
import {
  bytesToHex,
  FIXTURE_DEMO_PLAINTEXT,
  FIXTURE_FILE_PLAINTEXT_UTF8,
  FIXTURE_MASTER_KEY_HEX,
  FIXTURE_RECOVERY_CODE,
  hexToBytes,
} from './test/cryptoVectorFixtures.ts';

const VECTORS_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '../docs/crypto/vectors/pear-crypt-vectors-v1.json',
);

function loadCommittedVectors(): CryptoVectorsDocument {
  return parseCryptoVectorsDocument(JSON.parse(readFileSync(VECTORS_PATH, 'utf8')));
}

describe('crypto vectors contract', () => {
  it('builds deterministic vectors that roundtrip', async () => {
    const doc = await buildCryptoVectorsDocument();

    expect(doc.vectors.fileBlob).toMatchObject({
      decryptedUtf8: FIXTURE_FILE_PLAINTEXT_UTF8,
    });
    expect(doc.vectors.demoSandbox).toMatchObject({
      decrypted: FIXTURE_DEMO_PLAINTEXT,
    });
    expect(doc.vectors.masterKeyWrap).toMatchObject({
      pbkdf2Legacy: { unwrappedMasterKeyHex: FIXTURE_MASTER_KEY_HEX },
      argon2idModern: { unwrappedMasterKeyHex: FIXTURE_MASTER_KEY_HEX },
      fullWrapRoundtrip: { unwrappedMasterKeyHex: FIXTURE_MASTER_KEY_HEX },
    });
    expect(doc.vectors.recoveryCode).toEqual({
      input: FIXTURE_RECOVERY_CODE,
      normalized: 'ABCDEFGHJKLMNPRSTUVW',
    });
  });

  it('matches committed docs/crypto/vectors/pear-crypt-vectors-v1.json', async () => {
    const built = await buildCryptoVectorsDocument();
    const update = process.env.UPDATE_CRYPTO_VECTORS === '1';

    if (update) {
      mkdirSync(dirname(VECTORS_PATH), { recursive: true });
      writeFileSync(VECTORS_PATH, `${JSON.stringify(built, null, 2)}\n`, 'utf8');
    }

    const committed = loadCommittedVectors();
    expect(built).toEqual(committed);
  });

  it('decrypts committed ciphertext', async () => {
    const { fixtures, vectors } = loadCommittedVectors();
    const masterKeyRaw = hexToBytes(fixtures.masterKeyHex);
    const masterKey = await importMasterKeyRaw(masterKeyRaw);

    const filePlain = await decryptBytes(
      masterKeyRaw,
      fixtures.fileUid,
      hexToBytes(vectors.fileBlob.ciphertextHex),
      vectors.fileBlob.bindAt,
    );
    expect(new TextDecoder().decode(filePlain)).toBe(vectors.fileBlob.plaintextUtf8);

    const metadata = await decryptFileMetadata(
      masterKey,
      fixtures.metaUid,
      vectors.metadata.ciphertextBase64,
      vectors.metadata.bindAt,
    );
    expect(metadata).toEqual(vectors.metadata.plaintext);

    const share = await decryptShareEnvelope(
      hexToBytes(fixtures.shareKeyHex),
      fixtures.sharePublicId,
      hexToBytes(vectors.shareEnvelope.ciphertextHex),
    );
    expect(share).toMatchObject({
      filename: vectors.shareEnvelope.filename,
      mime: vectors.shareEnvelope.mime,
    });
    expect(bytesToHex(share.bytes)).toBe(vectors.shareEnvelope.plaintextHex);

    const pbkdf2 = vectors.masterKeyWrap.pbkdf2Legacy;
    const pbkdf2Key = await derivePasswordKey(pbkdf2.password, base64ToBytes(pbkdf2.saltBase64));
    const pbkdf2Raw = await decryptWithKey(pbkdf2Key, pbkdf2.payload);
    expect(bytesToHex(pbkdf2Raw)).toBe(pbkdf2.unwrappedMasterKeyHex);

    const argon2 = vectors.masterKeyWrap.argon2idModern;
    const argon2Key = await deriveArgon2idKey(argon2.password, base64ToBytes(argon2.saltBase64));
    const argon2Raw = await decryptWithKey(argon2Key, argon2.payload);
    expect(bytesToHex(argon2Raw)).toBe(argon2.unwrappedMasterKeyHex);

    const fullWrap = vectors.masterKeyWrap.fullWrapRoundtrip;
    const unlocked = await unwrapMasterKey(fixtures.wrapPassword, {
      keySalt: fullWrap.keySalt,
      wrappedMasterKey: JSON.stringify(fullWrap.wrappedMasterKey),
      keyVersion: E2EE_WRAP_VERSION_VAULT,
    });
    expect(bytesToHex(await exportMasterKeyRaw(unlocked))).toBe(fullWrap.unwrappedMasterKeyHex);

    const demo = vectors.demoSandbox;
    expect(await decryptDemoText(demo.ciphertext, demo.password)).toBe(demo.plaintext);
    const demoParts = unpackDemoCiphertext(demo.ciphertext);
    expect(bytesToHex(demoParts.salt)).toBe(demo.unpacked.saltHex);
    expect(bytesToHex(demoParts.iv)).toBe(demo.unpacked.ivHex);
    expect(bytesToHex(demoParts.data)).toBe(demo.unpacked.dataHex);
  });
});

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildCryptoVectorsDocument } from './test/buildCryptoVectorsDocument.ts';
import { parseCryptoVectorsDocument } from './test/cryptoVectorsTypes.ts';
import {
  FIXTURE_DEMO_PLAINTEXT,
  FIXTURE_FILE_PLAINTEXT_UTF8,
  FIXTURE_MASTER_KEY_HEX,
  FIXTURE_RECOVERY_CODE,
} from './test/cryptoVectorFixtures.ts';

const VECTORS_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '../docs/crypto/vectors/pear-crypt-vectors-v1.json',
);

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

    const committed = parseCryptoVectorsDocument(JSON.parse(readFileSync(VECTORS_PATH, 'utf8')));
    expect(built).toEqual(committed);
  });
});

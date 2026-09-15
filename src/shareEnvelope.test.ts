import { describe, expect, it } from 'vitest';
import { SHARE_BLOB_VERSION, SHARE_KEY_BYTES } from './constants.ts';
import {
  decryptShareEnvelope,
  encryptShareEnvelope,
  generateShareKey,
} from './shareEnvelope.ts';

describe('shareEnvelope', () => {
  it('roundtrips a PDF payload bound to the public id', async () => {
    const shareKey = generateShareKey();
    expect(shareKey.byteLength).toBe(SHARE_KEY_BYTES);

    const pdf = new TextEncoder().encode('%PDF-1.4 analysis');
    const encrypted = await encryptShareEnvelope(shareKey, 'share-public-1', {
      filename: 'ОАК.pdf',
      mime: 'application/pdf',
      bytes: pdf,
    });

    expect(encrypted[0]).toBe(SHARE_BLOB_VERSION);
    const decrypted = await decryptShareEnvelope(shareKey, 'share-public-1', encrypted);
    expect(decrypted.filename).toBe('ОАК.pdf');
    expect(decrypted.mime).toBe('application/pdf');
    expect(new TextDecoder().decode(decrypted.bytes)).toBe('%PDF-1.4 analysis');
  });

  it('rejects a wrong key, public id, or truncated payload', async () => {
    const shareKey = generateShareKey();
    const encrypted = await encryptShareEnvelope(shareKey, 'share-a', {
      filename: 'scan.pdf',
      mime: 'application/pdf',
      bytes: new Uint8Array([1, 2, 3]),
    });

    await expect(decryptShareEnvelope(shareKey, 'share-a', encrypted.slice(0, 8)))
      .rejects.toMatchObject({ code: 'invalidShareEnvelope' });
    await expect(decryptShareEnvelope(generateShareKey(), 'share-a', encrypted))
      .rejects.toMatchObject({ code: 'invalidShareKey' });
    await expect(decryptShareEnvelope(shareKey, 'share-b', encrypted))
      .rejects.toMatchObject({ code: 'invalidShareKey' });
    await expect(decryptShareEnvelope(new Uint8Array(16), 'share-a', encrypted))
      .rejects.toMatchObject({ code: 'invalidShareKey' });
  });
});

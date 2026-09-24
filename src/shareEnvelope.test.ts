import { describe, expect, it } from 'vitest';
import { AES_GCM_IV_BYTES, SHARE_BLOB_VERSION, SHARE_KEY_BYTES } from './constants.ts';
import { packVersionedBlob } from './wire/blobFrame.ts';
import {
  decryptShareEnvelope,
  encodeShareAad,
  encryptShareEnvelope,
  generateShareKey,
} from './share/envelope.ts';

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

    const blankMime = await encryptShareEnvelope(shareKey, 'share-public-1', {
      filename: 'scan.pdf',
      mime: '',
      bytes: pdf,
    });
    expect((await decryptShareEnvelope(shareKey, 'share-public-1', blankMime)).mime).toBe(
      'application/pdf',
    );
  });

  it('rejects a wrong key, public id, or truncated payload', async () => {
    const shareKey = generateShareKey();
    const encrypted = await encryptShareEnvelope(shareKey, 'share-a', {
      filename: 'scan.pdf',
      mime: 'application/pdf',
      bytes: new Uint8Array([1, 2, 3]),
    });

    await expect(
      decryptShareEnvelope(shareKey, 'share-a', encrypted.slice(0, 8)),
    ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });
    await expect(
      decryptShareEnvelope(generateShareKey(), 'share-a', encrypted),
    ).rejects.toMatchObject({ code: 'invalidShareKey' });
    await expect(decryptShareEnvelope(shareKey, 'share-b', encrypted)).rejects.toMatchObject({
      code: 'invalidShareKey',
    });
    await expect(
      decryptShareEnvelope(new Uint8Array(16), 'share-a', encrypted),
    ).rejects.toMatchObject({ code: 'invalidShareKey' });
  });

  it('rejects a header that is too long, truncated, or not JSON', async () => {
    const shareKey = generateShareKey();
    const publicId = 'share-bad';

    await expect(
      encryptShareEnvelope(shareKey, publicId, {
        filename: 'x'.repeat(70_000),
        mime: 'application/pdf',
        bytes: new Uint8Array([1]),
      }),
    ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });

    const key = await crypto.subtle.importKey('raw', shareKey, { name: 'AES-GCM' }, false, [
      'encrypt',
    ]);
    const seal = async (plaintext: Uint8Array) => {
      const iv = new Uint8Array(AES_GCM_IV_BYTES);
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, additionalData: encodeShareAad(publicId) },
          key,
          plaintext,
        ),
      );

      return packVersionedBlob(SHARE_BLOB_VERSION, iv, ciphertext);
    };

    await expect(
      decryptShareEnvelope(shareKey, publicId, await seal(new Uint8Array([1]))),
    ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });
    await expect(
      decryptShareEnvelope(shareKey, publicId, await seal(new Uint8Array([0, 10, 1, 2]))),
    ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });
    await expect(
      decryptShareEnvelope(
        shareKey,
        publicId,
        await seal(new TextEncoder().encode(`${String.fromCharCode(0, 1)}{`)),
      ),
    ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });

    const header = new TextEncoder().encode(JSON.stringify({ filename: 'a.pdf', mime: '  ' }));
    const prefix = new Uint8Array(2);
    new DataView(prefix.buffer).setUint16(0, header.byteLength, false);
    const body = new Uint8Array(prefix.byteLength + header.byteLength + 1);
    body.set(prefix, 0);
    body.set(header, 2);
    const decrypted = await decryptShareEnvelope(shareKey, publicId, await seal(body));
    expect(decrypted.mime).toBe('application/pdf');
    expect(decrypted.filename).toBe('a.pdf');
  });

  it('requires Web Crypto when sealing a share', async () => {
    const subtle = globalThis.crypto.subtle;
    Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });

    await expect(
      encryptShareEnvelope(new Uint8Array(SHARE_KEY_BYTES), 'id', {
        filename: 'a.pdf',
        mime: 'application/pdf',
        bytes: new Uint8Array([1]),
      }),
    ).rejects.toMatchObject({ code: 'webCryptoUnavailable' });

    Object.defineProperty(globalThis.crypto, 'subtle', { value: subtle, configurable: true });
  });
});

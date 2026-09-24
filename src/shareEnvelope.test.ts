import { describe, expect, it } from 'vitest';
import {
  AES_GCM_IV_BYTES,
  E2EE_BLOB_OVERHEAD,
  SHARE_BLOB_VERSION,
  SHARE_KEY_BYTES,
} from './constants.ts';
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

    const emptyBody = await encryptShareEnvelope(shareKey, 'share-public-1', {
      filename: 'empty.pdf',
      mime: 'application/pdf',
      bytes: new Uint8Array(),
    });
    const emptyDecrypted = await decryptShareEnvelope(shareKey, 'share-public-1', emptyBody);
    expect(emptyDecrypted.filename).toBe('empty.pdf');
    expect(emptyDecrypted.bytes.byteLength).toBe(0);
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

    const headerNoMime = new TextEncoder().encode(JSON.stringify({ filename: 'a.pdf' }));
    const noMimePrefix = new Uint8Array(2);
    new DataView(noMimePrefix.buffer).setUint16(0, headerNoMime.byteLength, false);
    const noMimeBody = new Uint8Array(noMimePrefix.byteLength + headerNoMime.byteLength);
    noMimeBody.set(noMimePrefix, 0);
    noMimeBody.set(headerNoMime, 2);
    expect((await decryptShareEnvelope(shareKey, publicId, await seal(noMimeBody))).mime).toBe(
      'application/pdf',
    );
  });

  it('rejects an empty filename after sealing', async () => {
    const shareKey = generateShareKey();
    for (const filename of ['', '   ']) {
      const encrypted = await encryptShareEnvelope(shareKey, 'share-empty-name', {
        filename,
        mime: 'application/pdf',
        bytes: new Uint8Array([1]),
      });
      await expect(
        decryptShareEnvelope(shareKey, 'share-empty-name', encrypted),
      ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });
    }
  });

  it('accepts a header of 65535 bytes and rejects 65536', async () => {
    const shareKey = generateShareKey();
    const wrapperLength = new TextEncoder().encode(
      JSON.stringify({ filename: '', mime: 'application/pdf' }),
    ).byteLength;
    const atLimit = 'x'.repeat(65535 - wrapperLength);
    const overLimit = 'x'.repeat(65536 - wrapperLength);

    const encrypted = await encryptShareEnvelope(shareKey, 'share-limit', {
      filename: atLimit,
      mime: 'application/pdf',
      bytes: new Uint8Array([1]),
    });
    expect((await decryptShareEnvelope(shareKey, 'share-limit', encrypted)).filename).toBe(atLimit);

    await expect(
      encryptShareEnvelope(shareKey, 'share-limit', {
        filename: overLimit,
        mime: 'application/pdf',
        bytes: new Uint8Array([1]),
      }),
    ).rejects.toMatchObject({ code: 'invalidShareEnvelope' });
  });

  it('rejects a non-share version and a key that is not 32 bytes', async () => {
    const shareKey = generateShareKey();
    const encrypted = await encryptShareEnvelope(shareKey, 'share-a', {
      filename: 'scan.pdf',
      mime: 'application/pdf',
      bytes: new Uint8Array([1]),
    });
    const wrongVersion = new Uint8Array(E2EE_BLOB_OVERHEAD);
    wrongVersion[0] = 2;

    await expect(decryptShareEnvelope(shareKey, 'share-a', wrongVersion)).rejects.toMatchObject({
      code: 'invalidShareEnvelope',
    });

    for (const length of [31, 33]) {
      const key = new Uint8Array(length);
      await expect(
        encryptShareEnvelope(key, 'share-a', {
          filename: 'scan.pdf',
          mime: 'application/pdf',
          bytes: new Uint8Array([1]),
        }),
      ).rejects.toMatchObject({ code: 'invalidShareKey' });
      await expect(decryptShareEnvelope(key, 'share-a', encrypted)).rejects.toMatchObject({
        code: 'invalidShareKey',
      });
    }
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

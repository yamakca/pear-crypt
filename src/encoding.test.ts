import { describe, expect, it } from 'vitest';
import { PearKeepCryptoError } from './errors.ts';
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  concatBytes,
} from './encoding.ts';

describe('encoding', () => {
  it('roundtrips bytes through base64', () => {
    const input = new Uint8Array([0, 1, 2, 255]);
    expect(Array.from(base64ToBytes(bytesToBase64(input)))).toEqual(Array.from(input));
  });

  it('roundtrips bytes through base64url without padding', () => {
    const input = new Uint8Array([0, 1, 2, 250, 255]);
    const encoded = bytesToBase64Url(input);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(Array.from(base64UrlToBytes(encoded))).toEqual(Array.from(input));
  });

  it('rejects empty base64url input', () => {
    expect(() => base64UrlToBytes('   ')).toThrow(PearKeepCryptoError);
  });

  it('concatenates byte parts in order', () => {
    expect(Array.from(concatBytes([new Uint8Array([1]), new Uint8Array([2, 3])]))).toEqual([
      1, 2, 3,
    ]);
  });

  it('rejects invalid base64 strings', () => {
    expect(() => base64ToBytes('!!!')).toThrow(PearKeepCryptoError);
    expect(() => base64ToBytes('')).toThrow(PearKeepCryptoError);
    expect(() => base64ToBytes(1 as unknown as string)).toThrow(PearKeepCryptoError);
    expect(() => base64UrlToBytes(1 as unknown as string)).toThrow(PearKeepCryptoError);
    expect(() => base64UrlToBytes('A')).toThrow(PearKeepCryptoError);

    const input = new Uint8Array([0]);
    expect(Array.from(base64ToBytes(`  ${bytesToBase64(input)}  `))).toEqual([0]);
    expect(Array.from(base64UrlToBytes(`  ${bytesToBase64Url(input)}  `))).toEqual([0]);

    try {
      base64ToBytes('!!!');
    } catch (error) {
      expect(error).toMatchObject({ code: 'invalidEncoding' });
    }
  });
});

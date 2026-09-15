import { describe, expect, it } from 'vitest';
import { PearKeepCryptoError } from './errors.ts';
import { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url } from './encoding.ts';

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

  it('rejects invalid base64 strings', () => {
    expect(() => base64ToBytes('!!!')).toThrow(PearKeepCryptoError);
    expect(() => base64ToBytes('')).toThrow(PearKeepCryptoError);

    try {
      base64ToBytes('!!!');
    } catch (error) {
      expect(error).toMatchObject({ code: 'invalidEncoding' });
    }
  });
});

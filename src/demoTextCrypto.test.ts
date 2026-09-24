import { describe, expect, it } from 'vitest';
import { AES_GCM_IV_BYTES, E2EE_SALT_BYTES } from './constants.ts';
import { bytesToBase64 } from './encoding.ts';
import {
  decryptDemoText,
  encryptDemoText,
  packDemoCiphertext,
  unpackDemoCiphertext,
} from './demo/textCrypto.ts';

describe('demoTextCrypto', () => {
  it('encrypts to an opaque blob without field names', async () => {
    const ciphertext = await encryptDemoText('паспорт 1234', 'secret-demo');
    expect(ciphertext.startsWith('pk1.')).toBe(true);
    expect(ciphertext).not.toContain('salt');
    expect(ciphertext).not.toContain('паспорт');
    expect(ciphertext).not.toContain('{');

    expect(await decryptDemoText(ciphertext, 'secret-demo')).toBe('паспорт 1234');
    expect(await decryptDemoText(`  ${ciphertext}\n`, 'secret-demo')).toBe('паспорт 1234');
  });

  it('rejects a wrong password', async () => {
    const ciphertext = await encryptDemoText('secret text', 'right');
    await expect(decryptDemoText(ciphertext, 'wrong')).rejects.toThrow();
  });

  it('round-trips a packed blob through unpack and pack', async () => {
    const ciphertext = await encryptDemoText('cross-browser', 'pw');
    const parts = unpackDemoCiphertext(ciphertext);
    const again = packDemoCiphertext(parts);
    expect(await decryptDemoText(again, 'pw')).toBe('cross-browser');
  });

  it('rejects an invalid blob', () => {
    expect(() => unpackDemoCiphertext('not-ciphertext')).toThrow('invalid-envelope');
    expect(() => unpackDemoCiphertext('pk1.@@@')).toThrow();
    expect(() => unpackDemoCiphertext('pk1.AQID')).toThrow('invalid-envelope');

    const wrongVersion = new Uint8Array(1 + E2EE_SALT_BYTES + AES_GCM_IV_BYTES + 1);
    wrongVersion[0] = 2;
    expect(() => unpackDemoCiphertext(`pk1.${bytesToBase64(wrongVersion)}`)).toThrow(
      'invalid-envelope',
    );
  });

  it('rejects an empty password and a malformed envelope', async () => {
    await expect(encryptDemoText('text', '')).rejects.toThrow('empty-password');
    await expect(decryptDemoText('pk1.AAAA', '')).rejects.toThrow('empty-password');

    expect(() =>
      packDemoCiphertext({
        salt: new Uint8Array(4),
        iv: new Uint8Array(AES_GCM_IV_BYTES),
        data: new Uint8Array([1]),
      }),
    ).toThrow('invalid-envelope');
    expect(() =>
      packDemoCiphertext({
        salt: new Uint8Array(E2EE_SALT_BYTES),
        iv: new Uint8Array(AES_GCM_IV_BYTES - 1),
        data: new Uint8Array([1]),
      }),
    ).toThrow('invalid-envelope');
  });

  it('treats a space as a password and roundtrips an empty plaintext', async () => {
    const spaced = await encryptDemoText('text', ' ');
    expect(await decryptDemoText(spaced, ' ')).toBe('text');
    expect(await decryptDemoText(await encryptDemoText('', 'pw'), 'pw')).toBe('');
  });
});

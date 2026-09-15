import { describe, expect, it } from 'vitest';
import {
  decryptDemoText,
  encryptDemoText,
  packDemoCiphertext,
  unpackDemoCiphertext,
} from './demoTextCrypto.ts';

describe('demoTextCrypto', () => {
  it('encrypts to an opaque blob without field names', async () => {
    const ciphertext = await encryptDemoText('паспорт 1234', 'secret-demo');
    expect(ciphertext.startsWith('pk1.')).toBe(true);
    expect(ciphertext).not.toContain('salt');
    expect(ciphertext).not.toContain('паспорт');
    expect(ciphertext).not.toContain('{');

    expect(await decryptDemoText(ciphertext, 'secret-demo')).toBe('паспорт 1234');
  });

  it('rejects a wrong password', async () => {
    const ciphertext = await encryptDemoText('secret text', 'right');
    await expect(decryptDemoText(ciphertext, 'wrong')).rejects.toThrow();
  });

  it('round-trips a packed blob in another browser', async () => {
    const ciphertext = await encryptDemoText('cross-browser', 'pw');
    const parts = unpackDemoCiphertext(ciphertext);
    const again = packDemoCiphertext(parts);
    expect(await decryptDemoText(again, 'pw')).toBe('cross-browser');
  });

  it('rejects an invalid blob', () => {
    expect(() => unpackDemoCiphertext('not-ciphertext')).toThrow('invalid-envelope');
    expect(() => unpackDemoCiphertext('pk1.@@@')).toThrow();
  });
});

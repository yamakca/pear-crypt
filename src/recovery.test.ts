import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateRecoveryCode, normalizeRecoveryCode } from './recovery/code.ts';

describe('recovery codes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('generates 25 independent crockford characters', () => {
    const code = generateRecoveryCode();
    const normalized = normalizeRecoveryCode(code);

    expect(code).toMatch(/^[A-Z2-9]{5}(?:-[A-Z2-9]{5}){4}$/);
    expect(normalized).toHaveLength(25);
  });

  it('maps 25 independent bytes onto 25 alphabet characters', () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(
      (array: ArrayBufferView | null) => {
        const isArrayMissing = array === null;
        if (isArrayMissing) {
          return array;
        }

        const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
        for (let index = 0; index < bytes.length; index += 1) {
          bytes[index] = index;
        }

        return array;
      },
    );

    const normalized = normalizeRecoveryCode(generateRecoveryCode());
    expect(normalized).toBe('ABCDEFGHJKLMNPQRSTUVWXYZ2');
    expect(normalized.slice(0, 5)).not.toBe(normalized.slice(20, 25));
  });

  it('fails when the random source does not return a full buffer', () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockReturnValue([] as unknown as Uint8Array);

    expect(() => generateRecoveryCode()).toThrow('recovery code generation failed');
  });

  it('fails when a random byte falls outside the alphabet', () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockReturnValue([-1] as unknown as Uint8Array);

    expect(() => generateRecoveryCode()).toThrow('recovery alphabet index out of range');
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateRecoveryCode, normalizeRecoveryCode } from './recovery.ts';

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
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((array: ArrayBufferView | null) => {
      if (array === null) {
        return array;
      }

      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = index;
      }

      return array;
    });

    const normalized = normalizeRecoveryCode(generateRecoveryCode());
    expect(normalized).toBe('ABCDEFGHJKLMNPQRSTUVWXYZ2');
    expect(normalized.slice(0, 5)).not.toBe(normalized.slice(20, 25));
  });
});

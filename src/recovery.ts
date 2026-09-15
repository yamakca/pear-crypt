const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const RECOVERY_CODE_CHARS = 25;

export function generateRecoveryCode(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(RECOVERY_CODE_CHARS));
  const chars: string[] = [];

  for (let index = 0; index < RECOVERY_CODE_CHARS; index += 1) {
    if (index > 0 && index % 5 === 0) {
      chars.push('-');
    }

    const byte = bytes[index];
    if (byte === undefined) {
      throw new Error('recovery code generation failed');
    }

    // Alphabet length is 32, so byte % 32 is unbiased.
    const symbol = RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length];
    if (symbol === undefined) {
      throw new Error('recovery alphabet index out of range');
    }

    chars.push(symbol);
  }

  return chars.join('');
}

export function normalizeRecoveryCode(value: string): string {
  return value.toUpperCase().replace(/[^A-Z2-9]/g, '');
}

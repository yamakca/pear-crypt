const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const RECOVERY_GROUP_LENGTH = 5;
const RECOVERY_GROUP_COUNT = 5;
const RECOVERY_CODE_CHARS = RECOVERY_GROUP_LENGTH * RECOVERY_GROUP_COUNT;

export function generateRecoveryCode(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(RECOVERY_CODE_CHARS));
  const chars: string[] = [];

  for (let index = 0; index < RECOVERY_CODE_CHARS; index += 1) {
    const isPastFirstCharacter = index > 0;
    const isGroupBoundary = index % RECOVERY_GROUP_LENGTH === 0;
    if (isPastFirstCharacter && isGroupBoundary) {
      chars.push('-');
    }

    const byte = bytes[index];
    const isByteMissing = byte === undefined;
    if (isByteMissing) {
      throw new Error('recovery code generation failed');
    }

    // Alphabet length is a power of two, so reducing a random byte is unbiased.
    const symbol = RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length];
    const isSymbolMissing = symbol === undefined;
    if (isSymbolMissing) {
      throw new Error('recovery alphabet index out of range');
    }

    chars.push(symbol);
  }

  return chars.join('');
}

export function normalizeRecoveryCode(value: string): string {
  return value.toUpperCase().replace(/[^A-Z2-9]/g, '');
}

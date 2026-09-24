import { cryptoError, type CryptoErrorCode } from './errors.ts';

type WebCryptoErrorCode = Extract<
  CryptoErrorCode,
  'webCryptoUnavailable' | 'webCryptoUnavailableBrowser'
>;

/** Web Crypto is required for every key and blob operation. */
export function requireSubtleCrypto(code: WebCryptoErrorCode): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  const isSubtleMissing = subtle === undefined;
  if (isSubtleMissing) {
    throw cryptoError(code);
  }

  return subtle;
}

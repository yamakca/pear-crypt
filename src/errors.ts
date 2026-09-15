export const CryptoErrorCode = {
  invalidMasterKey: 'invalidMasterKey',
  invalidEncryptedFileFormat: 'invalidEncryptedFileFormat',
  invalidEncryptedMetadataFormat: 'invalidEncryptedMetadataFormat',
  corruptRecoveryData: 'corruptRecoveryData',
  invalidRecoveryCode: 'invalidRecoveryCode',
  corruptServerE2eeData: 'corruptServerE2eeData',
  wrongPassword: 'wrongPassword',
  invalidEncoding: 'invalidEncoding',
  webCryptoUnavailable: 'webCryptoUnavailable',
  webCryptoUnavailableBrowser: 'webCryptoUnavailableBrowser',
  invalidShareKey: 'invalidShareKey',
  invalidShareEnvelope: 'invalidShareEnvelope',
} as const;

export type CryptoErrorCode = typeof CryptoErrorCode[keyof typeof CryptoErrorCode];

export class PearKeepCryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode) {
    super(code);
    this.name = 'PearKeepCryptoError';
    this.code = code;
  }
}

export function cryptoError(code: CryptoErrorCode): PearKeepCryptoError {
  return new PearKeepCryptoError(code);
}

export function isPearKeepCryptoError(
  error: unknown,
  code?: CryptoErrorCode,
): error is PearKeepCryptoError {
  return error instanceof PearKeepCryptoError && (code === undefined || error.code === code);
}

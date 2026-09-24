export type { WrappedMasterKeyPayload, E2eeKeyMaterial, WrapKdfParams } from './types.ts';

export {
  deriveArgon2idKey,
  derivePasswordKey,
  decryptWithKey,
  encryptWithKey,
  encryptWithKeyLegacy,
  exportMasterKeyRaw,
  generateMasterKey,
  generateSalt,
  importMasterKeyRaw,
  isLegacyWrapPayload,
} from './masterKeyCrypto.ts';

export {
  deriveFileKey,
  deriveFileKeyFromRaw,
  deriveMetadataKey,
  deriveMetadataKeyFromRaw,
  deriveSettingsKey,
  deriveSettingsKeyFromRaw,
} from './keyMaterial.ts';

export {
  rewrapMasterKey,
  unwrapMasterKey,
  wrapMasterKey,
  wrappedMasterKeyNeedsKdfUpgrade,
} from './masterKeyWrap.ts';

export { parseWrappedMasterKeyPayload } from './payload.ts';

export { createE2eeSetup, createRecoveryWrap, unwrapMasterKeyWithRecovery } from './e2eeSetup.ts';

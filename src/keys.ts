export type { WrappedMasterKeyPayload, E2eeKeyMaterial } from './keys/types.ts';

export {
  exportMasterKeyRaw,
  generateMasterKey,
  generateSalt,
  importMasterKeyRaw,
} from './keys/masterKeyWrap.ts';

export {
  wrapMasterKey,
  unwrapMasterKey,
  deriveFileKey,
  deriveMetadataKey,
  deriveSettingsKey,
  rewrapMasterKey,
  wrappedMasterKeyNeedsKdfUpgrade,
  parseWrappedMasterKeyPayload,
} from './keys/masterKeyWrap.ts';

export {
  createRecoveryWrap,
  createE2eeSetup,
  unwrapMasterKeyWithRecovery,
} from './keys/e2eeSetup.ts';

export {
  derivePasswordKey,
  deriveArgon2idKey,
  encryptWithKey,
  encryptWithKeyLegacy,
  decryptWithKey,
  isLegacyWrapPayload,
} from './keys/masterKeyCrypto.ts';

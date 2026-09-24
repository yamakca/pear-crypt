import type { FileMetadataPlaintext } from '../metadata/metadata.ts';
import type { WrappedMasterKeyPayload } from '../keys/types.ts';

export interface CryptoVectorFixtures {
  masterKeyHex: string;
  wrapSaltHex: string;
  ivHex: string;
  shareKeyHex: string;
  fileUid: string;
  metaUid: string;
  sharePublicId: string;
  wrapPassword: string;
  demoPassword: string;
  bindAt: number;
  recoveryCode: string;
  recoveryCodeNormalized: string;
}

export interface CryptoVectorsDocument {
  specVersion: string;
  productVersion: string;
  description: string;
  fixtures: CryptoVectorFixtures;
  vectors: CryptoVectorsSection;
}

export interface CryptoVectorsSection {
  encoding: {
    base64: { inputHex: string; output: string };
    base64Url: { inputHex: string; output: string; roundtripHex: string };
    base64Roundtrip: { inputHex: string };
  };
  fileBlob: {
    plaintextUtf8: string;
    bindAt: number;
    ciphertextHex: string;
    decryptedUtf8: string;
  };
  metadata: {
    plaintext: FileMetadataPlaintext;
    bindAt: number;
    ciphertextBase64: string;
    decrypted: FileMetadataPlaintext;
  };
  shareEnvelope: {
    filename: string;
    mime: string;
    plaintextHex: string;
    shareUrlFragment: string;
    ciphertextHex: string;
    decrypted: {
      filename: string;
      mime: string;
      plaintextHex: string;
    };
  };
  masterKeyWrap: {
    pbkdf2Legacy: {
      password: string;
      saltBase64: string;
      payload: WrappedMasterKeyPayload;
      unwrappedMasterKeyHex: string;
    };
    argon2idModern: {
      password: string;
      saltBase64: string;
      payload: WrappedMasterKeyPayload;
      unwrappedMasterKeyHex: string;
    };
    fullWrapRoundtrip: {
      keySalt: string;
      wrappedMasterKey: WrappedMasterKeyPayload;
      unwrappedMasterKeyHex: string;
    };
  };
  demoSandbox: {
    plaintext: string;
    password: string;
    wirePrefix: string;
    ciphertext: string;
    decrypted: string;
    repackedCiphertext: string;
    unpacked: {
      saltHex: string;
      ivHex: string;
      dataHex: string;
    };
  };
  recoveryCode: {
    input: string;
    normalized: string;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  const isObject = typeof value === 'object';
  const isNotNull = value !== null;

  return isObject && isNotNull;
}

function isString(value: unknown): value is string {
  const isText = typeof value === 'string';

  return isText;
}

function isNumber(value: unknown): value is number {
  const isNumeric = typeof value === 'number';

  return isNumeric;
}

function assertRecord(value: unknown, label: string): Record<string, unknown> {
  const isObject = isRecord(value);
  if (!isObject) {
    throw new Error(`invalid crypto vectors: ${label}`);
  }

  return value;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  const isText = isString(value);
  if (!isText) {
    throw new Error(`invalid crypto vectors: fixtures.${key}`);
  }

  return value;
}

function requireNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  const isNumeric = isNumber(value);
  if (!isNumeric) {
    throw new Error(`invalid crypto vectors: fixtures.${key}`);
  }

  return value;
}

function parseFixtures(value: unknown): CryptoVectorFixtures {
  const fixtures = assertRecord(value, 'fixtures');

  return {
    masterKeyHex: requireString(fixtures, 'masterKeyHex'),
    wrapSaltHex: requireString(fixtures, 'wrapSaltHex'),
    ivHex: requireString(fixtures, 'ivHex'),
    shareKeyHex: requireString(fixtures, 'shareKeyHex'),
    fileUid: requireString(fixtures, 'fileUid'),
    metaUid: requireString(fixtures, 'metaUid'),
    sharePublicId: requireString(fixtures, 'sharePublicId'),
    wrapPassword: requireString(fixtures, 'wrapPassword'),
    demoPassword: requireString(fixtures, 'demoPassword'),
    bindAt: requireNumber(fixtures, 'bindAt'),
    recoveryCode: requireString(fixtures, 'recoveryCode'),
    recoveryCodeNormalized: requireString(fixtures, 'recoveryCodeNormalized'),
  };
}

function parseVectorsSection(value: Record<string, unknown>): CryptoVectorsSection {
  const requiredSections = [
    'encoding',
    'fileBlob',
    'metadata',
    'shareEnvelope',
    'masterKeyWrap',
    'demoSandbox',
    'recoveryCode',
  ] as const;

  for (const key of requiredSections) {
    const isSectionObject = isRecord(value[key]);
    if (!isSectionObject) {
      throw new Error(`invalid crypto vectors: vectors.${key}`);
    }
  }

  return value as unknown as CryptoVectorsSection;
}

export function parseCryptoVectorsDocument(value: unknown): CryptoVectorsDocument {
  const root = assertRecord(value, 'root');

  const specVersion = root.specVersion;
  const hasSpecVersion = isString(specVersion);
  if (!hasSpecVersion) {
    throw new Error('invalid crypto vectors: header');
  }

  const productVersion = root.productVersion;
  const hasProductVersion = isString(productVersion);
  if (!hasProductVersion) {
    throw new Error('invalid crypto vectors: header');
  }

  const description = root.description;
  const hasDescription = isString(description);
  if (!hasDescription) {
    throw new Error('invalid crypto vectors: header');
  }

  const vectors = assertRecord(root.vectors, 'vectors');

  return {
    specVersion,
    productVersion,
    description,
    fixtures: parseFixtures(root.fixtures),
    vectors: parseVectorsSection(vectors),
  };
}

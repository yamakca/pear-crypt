import type { FileMetadataPlaintext } from '../metadata.ts';
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
    base64: { inputHex: string, output: string };
    base64Url: { inputHex: string, output: string, roundtripHex: string };
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
  return typeof value === 'object' && value !== null;
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number';
}

function assertRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`invalid crypto vectors: ${label}`);
  }

  return value;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (!isString(value)) {
    throw new Error(`invalid crypto vectors: fixtures.${key}`);
  }

  return value;
}

function requireNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (!isNumber(value)) {
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
    if (!isRecord(value[key])) {
      throw new Error(`invalid crypto vectors: vectors.${key}`);
    }
  }

  return value as unknown as CryptoVectorsSection;
}

export function parseCryptoVectorsDocument(value: unknown): CryptoVectorsDocument {
  const root = assertRecord(value, 'root');

  if (!isString(root.specVersion) || !isString(root.productVersion) || !isString(root.description)) {
    throw new Error('invalid crypto vectors: header');
  }

  const vectors = assertRecord(root.vectors, 'vectors');

  return {
    specVersion: root.specVersion,
    productVersion: root.productVersion,
    description: root.description,
    fixtures: parseFixtures(root.fixtures),
    vectors: parseVectorsSection(vectors),
  };
}

/** Shared AES-GCM frame used by file blobs, metadata, and share envelopes. */
export const E2EE_BLOB_VERSION_LEGACY = 1;

export const E2EE_BLOB_VERSION = 2;

export const E2EE_VERSION_CONTENT = 1;

export const E2EE_VERSION_FULL = 2;

/** Label a caller may show instead of the encrypted file name. */
export const E2EE_PLACEHOLDER_LABEL = '—';

/** Leading version byte on every versioned blob. */
export const BLOB_VERSION_BYTES = 1;

/** AES-GCM nonce length used by every versioned blob. */
export const AES_GCM_IV_BYTES = 12;

/** AES-GCM authentication tag length. */
export const AES_GCM_TAG_BYTES = 16;

/** AES-256 key length in bits. */
export const AES_GCM_KEY_BITS = 256;

/** version byte + nonce + GCM tag */
export const E2EE_BLOB_OVERHEAD = BLOB_VERSION_BYTES + AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES;

/** Master-key wrap: password or PIN to a wrapped key. */
export const E2EE_PBKDF2_ITERATIONS = 600_000;

/** Wrapped master-key payload versions (AES-GCM envelope around the raw master key). */
export const E2EE_WRAP_PAYLOAD_VERSION_PBKDF2 = 1;
export const E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID = 2;

/** Argon2id params for wrap-key derivation. */
export const E2EE_ARGON2_MEMORY_KIB = 32 * 1024;
export const E2EE_ARGON2_ITERATIONS = 2;
export const E2EE_ARGON2_PARALLELISM = 1;
export const E2EE_ARGON2_HASH_LENGTH = 32;

export const E2EE_CONTENT_TYPE = 'application/x-pear-keep-e2ee-v1';

export const E2EE_MASTER_KEY_BYTES = 32;

export const E2EE_SALT_BYTES = 16;

/** Wrap secret is a password (`keyVersion`). */
export const E2EE_WRAP_VERSION_ACCOUNT = 1;

/** Wrap secret is a PIN (`keyVersion`). */
export const E2EE_WRAP_VERSION_VAULT = 2;

/** Suggested minimum length for a new PIN. The library does not enforce it. */
export const VAULT_PIN_MIN_LENGTH = 6;

/** Suggested maximum PIN length. The library does not enforce it. */
export const VAULT_PIN_MAX_LENGTH = 12;

/** Suggested minimum length for an older PIN. The library does not enforce it. */
export const VAULT_PIN_LEGACY_MIN_LENGTH = 4;

/**
 * @deprecated Prefer VAULT_PIN_MIN_LENGTH. Same value as the suggested minimum.
 */
export const VAULT_PIN_LENGTH = VAULT_PIN_MIN_LENGTH;

/** Share envelopes. */
export const SHARE_BLOB_VERSION = 1;

export const SHARE_KEY_BYTES = 32;

export const SHARE_MAX_BYTES = 50 * 1024 * 1024;

export const SHARE_TTL_HOURS = [1, 24, 168] as const;

export type ShareTtlHours = (typeof SHARE_TTL_HOURS)[number];

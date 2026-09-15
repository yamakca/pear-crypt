export const E2EE_BLOB_VERSION_LEGACY = 1;

export const E2EE_BLOB_VERSION = 2;

export const E2EE_VERSION_CONTENT = 1;

export const E2EE_VERSION_FULL = 2;

/** Placeholder label stored on server when metadata is encrypted. */
export const E2EE_PLACEHOLDER_LABEL = '—';

/** version byte + nonce + GCM tag */
export const E2EE_BLOB_OVERHEAD = 1 + 12 + 16;

export const E2EE_PBKDF2_ITERATIONS = 600_000;

/** Wrapped master-key payload versions (AES-GCM envelope around the raw master key). */
export const E2EE_WRAP_PAYLOAD_VERSION_PBKDF2 = 1;
export const E2EE_WRAP_PAYLOAD_VERSION_ARGON2ID = 2;

/** Argon2id params for wrap-key derivation (mobile-friendly). */
export const E2EE_ARGON2_MEMORY_KIB = 32 * 1024;
export const E2EE_ARGON2_ITERATIONS = 2;
export const E2EE_ARGON2_PARALLELISM = 1;
export const E2EE_ARGON2_HASH_LENGTH = 32;

export const E2EE_CONTENT_TYPE = 'application/x-pear-keep-e2ee-v1';

export const E2EE_MASTER_KEY_BYTES = 32;

export const E2EE_SALT_BYTES = 16;

/** Wrap derived from the account password. Auto-unlocks after login. */
export const E2EE_WRAP_VERSION_ACCOUNT = 1;

/** Wrap derived from a dedicated vault PIN that is never sent to the server. */
export const E2EE_WRAP_VERSION_VAULT = 2;

/** Minimum length for new / changed vault PINs. */
export const VAULT_PIN_MIN_LENGTH = 6;

/** Maximum vault PIN length (digits). */
export const VAULT_PIN_MAX_LENGTH = 12;

/** Legacy vault PINs still accepted for unlock until rebind. */
export const VAULT_PIN_LEGACY_MIN_LENGTH = 4;

/**
 * @deprecated Prefer VAULT_PIN_MIN_LENGTH. Kept as display default (= min).
 */
export const VAULT_PIN_LENGTH = VAULT_PIN_MIN_LENGTH;

export const SHARE_BLOB_VERSION = 1;

export const SHARE_KEY_BYTES = 32;

export const SHARE_MAX_BYTES = 50 * 1024 * 1024;

export const SHARE_TTL_HOURS = [1, 24, 168] as const;

export type ShareTtlHours = (typeof SHARE_TTL_HOURS)[number];

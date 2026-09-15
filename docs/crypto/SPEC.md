# pear-crypt — спецификация клиентского шифрования

**Версия spec:** 1.0.0  
**Реализация:** [`src/`](../../src/)  
**Test vectors:** [pear-crypt-vectors-v1.json](./vectors/pear-crypt-vectors-v1.json)

Документ описывает wire-format и криптографию **на клиенте**. Сервер хранит только ciphertext и метаданные синхронизации; расшифровка возможна только с master key или share key, которые сервер не получает.

---

## 1. Threat model (честно)

### Сервер не видит (при включённом E2EE)

- Содержимое файлов (blob ciphertext).
- Расшифрованные метаданные (имя, теги, комментарии) — на сервере placeholder `—`.
- Master key сейфа — только в обёртке (wrapped), ключ обёртки выводится из секрета пользователя локально.
- Share key — передаётся в фрагменте URL `#k=…`, который **не отправляется** на сервер при HTTP-запросе.

### Сервер видит

- Ciphertext файлов и share-blob'ов.
- `publicId` share-ссылки, срок (TTL), факт отзыва.
- Метаданные синхронизации: uid, размер, timestamps, `e2ee_version`, зашифрованный metadata blob.
- **Пароль входа** — может проверяться на сервере (не zero-knowledge login).
- **Публичные страницы** хост-приложения и сторонняя аналитика — вне scope E2EE blob'ов.

### Вне scope этого документа

- API auth, billing, rate limits бэкенда.
- Локальная сессия браузера (unlock, lockout) — UX-политика потребителя, не wire-format ciphertext на сервере.

---

## 2. Примитивы

| Примитив | Параметры |
|----------|-----------|
| Symmetric | AES-256-GCM |
| KDF (legacy wrap) | PBKDF2-HMAC-SHA256, **600 000** итераций |
| KDF (modern wrap) | Argon2id: **m=32768 KiB**, **t=2**, **p=1**, hash **32** bytes |
| Key derivation (subkeys) | HKDF-SHA256, salt = empty, `info` = UTF-8 scope string |
| Random | `crypto.getRandomValues` (salt 16 B, IV 12 B) |

Константы — `src/constants.ts`.

---

## 3. Master key

- 256-bit AES-GCM key (`E2EE_MASTER_KEY_BYTES = 32`).
- Генерируется на клиенте при включении E2EE.
- **Не** отправляется на сервер в открытом виде.

### 3.1 Обёртка master key (на сервере)

Поля аккаунта (`E2eeKeyMaterial`):

| Поле | Формат |
|------|--------|
| `key_salt` | base64, 16 bytes |
| `wrapped_master_key` | JSON string (см. ниже) |
| `key_version` | `1` = wrap от пароля аккаунта; `2` = wrap от PIN сейфа |
| `recovery_wrapped_master_key` | JSON string (см. §7) |

**WrappedMasterKeyPayload** (JSON):

```json
{
  "v": 2,
  "kdf": { "alg": "argon2id", "m": 32768, "t": 2, "p": 1 },
  "iv": "<base64, 12 bytes>",
  "data": "<base64, ciphertext+tag>"
}
```

| `v` | KDF для ключа обёртки |
|-----|------------------------|
| `1` (legacy) | PBKDF2 600k |
| `2` (modern) | Argon2id (параметры в `kdf` или default) |

Шифрование: AES-GCM, **без AAD**, plaintext = raw master key (32 bytes).

Секрет обёртки:

- `key_version=1` — пароль аккаунта (проверяется на сервере при логине, но для unwrap используется локально).
- `key_version=2` — **PIN сейфа** (цифры, 6–12 для новых; legacy 4+); **не отправляется на сервер**.

---

## 4. Производные ключи (HKDF)

Из raw master key (32 B) через HKDF-SHA256 (`info` = scope, salt пустой):

| Scope | `info` string | Назначение |
|-------|---------------|------------|
| File blob | `pear-keep-file:{uid}` | Содержимое файла |
| Metadata | `pear-keep-meta:{uid}` | JSON метаданных |
| Settings | `pear-keep-settings` | Зашифрованные user settings |
| Search index | `pear-keep-search:{uid}` | Зашифрованный индекс поиска (опционально у потребителя) |

`uid` — стабильный идентификатор файла/папки на клиенте.

---

## 5. File blob (содержимое файла)

### Wire format (binary)

```
[version: u8][iv: 12 bytes][ciphertext || gcm_tag: variable]
```

| version | AAD при decrypt |
|---------|-----------------|
| `1` (`E2EE_BLOB_VERSION_LEGACY`) | **нет** (legacy) |
| `2` (`E2EE_BLOB_VERSION`) | `pear-keep-file:{uid}:{bindAt}` UTF-8 |

- `bindAt` — Unix ms «привязки» содержимого (`contentUpdatedAt`); metadata-only `updatedAt` не ломает decrypt.
- Пустой plaintext → пустой blob (без шифрования).
- Overhead: `1 + 12 + 16` bytes (`E2EE_BLOB_OVERHEAD`).

**Remote content type:** `application/x-pear-keep-e2ee-v1`

---

## 6. Metadata blob

Тот же binary layout, что §5, но:

- Ключ: HKDF scope `pear-keep-meta:{uid}`.
- AAD (v2): `pear-keep-meta:{uid}:{bindAt}`.
- Plaintext: UTF-8 JSON:

```json
{
  "label": "string",
  "tags": "optional string",
  "comments": "optional string",
  "extension": "optional string",
  "marker": "optional string",
  "type": "optional mime or inode/directory",
  "contentUpdatedAt": "optional number",
  "contentDigest": "optional hex digest"
}
```

На сервере при `e2ee_version >= 2` поле `label` = `—` (`E2EE_PLACEHOLDER_LABEL`).

Хранение: base64 от binary payload.

---

## 7. Recovery code

- Формат: 25 символов из `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, группы по 5 через `-`.
- Нормализация: upper case, удалить не-alphanumeric.
- Отдельная обёртка master key в `recovery_wrapped_master_key`:

```json
{
  "salt": "<base64, 16 B>",
  "wrapped": "<JSON WrappedMasterKeyPayload>"
}
```

Секрет KDF = normalized recovery code. **Не** хранится на сервере в открытом виде.

---

## 8. Share link («Поделиться»)

### 8.1 Ключ

- 32 random bytes (`SHARE_KEY_BYTES`).
- В URL: `#k={base64url(shareKey)}` — без padding, `-`/`_` вместо `+`/`/`.

Пример fragment (test vector): `#k=EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8`

### 8.2 Ciphertext на сервере

Binary layout:

```
[version: u8=1][iv: 12][ciphertext+tag]
```

- AES-256-GCM, key = raw share key.
- AAD: `pear-keep-share:{publicId}` UTF-8.
- Plaintext inner format:

```
[header_len: u16 BE][header_json UTF-8][file_bytes]
```

`header_json`:

```json
{ "filename": "…", "mime": "application/pdf" }
```

Share key **не** равен PIN сейфа и **не** derived от master key.

---

## 9. Demo sandbox (короткий текст)

Упрощённый demo wire-format (короткий текст, не файлы):

- Prefix: `pk1.`
- Base64 binary: `[ver=1][salt 16][iv 12][ciphertext+tag]`
- KDF: PBKDF2 600k (как legacy wrap), **не** Argon2id.
- Пароль demo — локальный PIN; **не** логин и **не** отправляется на сервер.

См. `src/demoTextCrypto.ts`. Интерактивная проверка: репозиторий **pear-crypt-demo** (`npm run dev`). В проде файлы шифруются master key (§5), не demo password.

---

## 10. User settings (кратко)

Binary как §5, version 2, AAD `pear-keep-settings:__pear_keep_user_settings__:{bindAt}`, ключ HKDF scope `pear-keep-settings`. JSON schema настроек — у потребителя библиотеки.

---

## 11. Кодирование

- **base64:** standard, `btoa`/`atob` semantics.
- **base64url:** без `=`, `-`/`_`; см. test vector `encoding.base64Url`.

---

## 12. Test vectors

Файл [vectors/pear-crypt-vectors-v1.json](./vectors/pear-crypt-vectors-v1.json) содержит **синтетические** секреты и детерминированные ciphertext (IV зафиксирован в генераторе).

| Секция | Проверяет |
|--------|-----------|
| `encoding` | base64 / base64url |
| `fileBlob` | §5 encrypt/decrypt |
| `metadata` | §6 |
| `shareEnvelope` | §8 |
| `masterKeyWrap` | PBKDF2 legacy + Argon2id modern + full `wrapMasterKey` |
| `demoSandbox` | §9 |
| `recoveryCode` | нормализация |

При изменении `src/` обновите vectors в этом репозитории и прогоните contract test у потребителя (если есть).

---

## 13. Соответствие реализации

| Spec | Код |
|------|-----|
| §3–4 | `src/keys/*`, `keyMaterial.ts` |
| §5 | `src/blobCore.ts` |
| §6 | `src/metadata.ts` |
| §7 | `src/recovery.ts`, `keys/e2eeSetup.ts` |
| §8 | `src/shareEnvelope.ts` |
| §9 | `src/demoTextCrypto.ts` |

Ошибки — `PearKeepCryptoError` с машинными кодами; локализация — у потребителя.

---

## 14. Changelog spec

| Version | Change |
|---------|--------|
| 1.0.0 | Initial spec + vectors |
| 1.1.0 | Error codes instead of i18n in library |
| 1.2.0 | Spec + vectors in `docs/crypto/` |

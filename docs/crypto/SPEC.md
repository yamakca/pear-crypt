# pear-crypt — спецификация клиентского шифрования

**Версия spec:** 1.0.0  
**Реализация:** [`src/`](../../src/)  
**Test vectors:** [pear-crypt-vectors-v1.json](./vectors/pear-crypt-vectors-v1.json)

Документ описывает wire-format и криптографию библиотеки. Ciphertext не содержит master key, пароль, PIN, recovery code и share key. Эти секреты остаются у вызывающего кода и используются только как вход KDF или AES-GCM.

---

## 1. Что защищает формат

- Содержимое файла и JSON метаданных шифруются отдельными ключами, выведенными из master key.
- Master key попадает наружу только внутри AES-GCM-обёртки. Ключ обёртки выводится из пароля, PIN или recovery code.
- Share-конверт шифруется отдельным случайным share key, не связанным с master key.
- Константа `E2EE_PLACEHOLDER_LABEL` (`—`) — метка, которую вызывающий код может хранить вместо открытого имени.

Библиотека не хранит ciphertext и секреты между вызовами.

---

## 2. Примитивы

| Примитив                 | Параметры                                                      |
| ------------------------ | -------------------------------------------------------------- |
| Symmetric                | AES-256-GCM                                                    |
| KDF (legacy wrap)        | PBKDF2-HMAC-SHA256, **600 000** итераций                       |
| KDF (modern wrap)        | Argon2id: **m=32768 KiB**, **t=2**, **p=1**, hash **32** bytes |
| Key derivation (subkeys) | HKDF-SHA256, salt = empty, `info` = UTF-8 scope string         |
| Random                   | `crypto.getRandomValues` (salt 16 B, IV 12 B)                  |

Константы — `src/constants.ts`.

---

## 3. Master key

- 256-bit AES-GCM key (`E2EE_MASTER_KEY_BYTES = 32`).
- Генерируется на клиенте при включении E2EE.
- В открытом виде из библиотеки наружу не отдаётся: только wrap и производные ключи.

### 3.1 Обёртка master key

`E2eeKeyMaterial`:

| Поле                       | Формат                                  |
| -------------------------- | --------------------------------------- |
| `keySalt`                  | base64, 16 bytes                        |
| `wrappedMasterKey`         | JSON string (см. ниже)                  |
| `keyVersion`               | `1` = wrap от пароля; `2` = wrap от PIN |
| `recoveryWrappedMasterKey` | JSON string (см. §7), необязательное    |

**WrappedMasterKeyPayload** (JSON):

```json
{
  "v": 2,
  "kdf": { "alg": "argon2id", "m": 32768, "t": 2, "p": 1 },
  "iv": "<base64, 12 bytes>",
  "data": "<base64, ciphertext+tag>"
}
```

| `v`          | KDF для ключа обёртки                    |
| ------------ | ---------------------------------------- |
| `1` (legacy) | PBKDF2 600k                              |
| `2` (modern) | Argon2id (параметры в `kdf` или default) |

Шифрование: AES-GCM, **без AAD**, plaintext = raw master key (32 bytes).

Секрет обёртки библиотека не хранит. Вызывающий код передаёт его в `wrapMasterKey` / `unwrapMasterKey`:

- `keyVersion = 1` (`E2EE_WRAP_VERSION_ACCOUNT`) — пароль.
- `keyVersion = 2` (`E2EE_WRAP_VERSION_VAULT`) — PIN. Константы длины: новые PIN 6–12 цифр, legacy от 4. Библиотека эти длины не проверяет.

---

## 4. Производные ключи (HKDF)

Из raw master key (32 B) через HKDF-SHA256 (`info` = scope, salt пустой):

| Scope     | `info` string          | Функция             |
| --------- | ---------------------- | ------------------- |
| File blob | `pear-keep-file:{uid}` | `deriveFileKey`     |
| Metadata  | `pear-keep-meta:{uid}` | `deriveMetadataKey` |
| Settings  | `pear-keep-settings`   | `deriveSettingsKey` |

Префиксы `pear-keep-*` — исторические имена wire-format v1. `uid` передаёт вызывающий код.

`encodeBlobAad` дополнительно принимает scope `pear-keep-search`. Отдельного формата поискового индекса в библиотеке нет.

---

## 5. File blob (содержимое файла)

### Wire format (binary)

```
[version: u8][iv: 12 bytes][ciphertext || gcm_tag: variable]
```

| version                          | AAD при decrypt                       |
| -------------------------------- | ------------------------------------- |
| `1` (`E2EE_BLOB_VERSION_LEGACY`) | **нет** (legacy)                      |
| `2` (`E2EE_BLOB_VERSION`)        | `pear-keep-file:{uid}:{bindAt}` UTF-8 |

- `bindAt` — число, которое вызывающий код подставляет в AAD. Для метаданных это обычно `contentUpdatedAt`.
- Пустой plaintext → пустой blob, без шифрования.
- Overhead: `1 + 12 + 16` bytes (`E2EE_BLOB_OVERHEAD`).
- Content type константы: `application/x-pear-keep-e2ee-v1` (`E2EE_CONTENT_TYPE`).

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
  "type": "optional string",
  "contentUpdatedAt": "optional number",
  "contentDigest": "optional hex digest"
}
```

Хранение у вызывающего кода: base64 от binary payload. Открытую подпись библиотека не кладёт в ciphertext; для неё есть `E2EE_PLACEHOLDER_LABEL`.

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

Секрет KDF = normalized recovery code. В конверт попадает только salt и wrapped payload.

---

## 8. Share envelope

### 8.1 Ключ

- 32 random bytes (`SHARE_KEY_BYTES`).
- В URL: `#k={base64url(shareKey)}` — без padding, `-`/`_` вместо `+`/`/`.

Пример fragment (test vector): `#k=EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8`

### 8.2 Ciphertext

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

Share key не выводится из master key и не равен PIN обёртки.

---

## 9. Demo sandbox (короткий текст)

Упрощённый demo wire-format (короткий текст, не файлы):

- Prefix: `pk1.`
- Base64 binary: `[ver=1][salt 16][iv 12][ciphertext+tag]`
- KDF: PBKDF2 600k, как legacy wrap, не Argon2id.

Код: `src/demo/textCrypto.ts`. Файлы и метаданные этим форматом не шифруются.

---

## 10. Кодирование

- **base64:** standard, `btoa`/`atob` semantics.
- **base64url:** без `=`, `-`/`_`; см. test vector `encoding.base64Url`.

---

## 11. Test vectors

Файл [vectors/pear-crypt-vectors-v1.json](./vectors/pear-crypt-vectors-v1.json) содержит **синтетические** секреты и детерминированные ciphertext (IV зафиксирован в генераторе).

| Секция          | Проверяет                                              |
| --------------- | ------------------------------------------------------ |
| `encoding`      | base64 / base64url                                     |
| `fileBlob`      | §5 encrypt/decrypt                                     |
| `metadata`      | §6                                                     |
| `shareEnvelope` | §8                                                     |
| `masterKeyWrap` | PBKDF2 legacy + Argon2id modern + full `wrapMasterKey` |
| `demoSandbox`   | §9                                                     |
| `recoveryCode`  | нормализация                                           |

После изменения `src/`: `npm run export:vectors`, затем `npm test`.

---

## 12. Соответствие реализации

| Spec | Код                                          |
| ---- | -------------------------------------------- |
| §3–4 | `src/keys/`                                  |
| §5   | `src/files/blob.ts`, `src/wire/blobFrame.ts` |
| §6   | `src/metadata/metadata.ts`                   |
| §7   | `src/recovery/`, `src/keys/e2eeSetup.ts`     |
| §8   | `src/share/envelope.ts`                      |
| §9   | `src/demo/textCrypto.ts`                     |
| §10  | `src/encoding.ts`                            |

Ошибки — `PearKeepCryptoError` с машинным кодом в `code`. Текст сообщения равен коду.

---

## 13. Changelog spec

| Version | Change                                 |
| ------- | -------------------------------------- |
| 1.0.0   | Initial spec + vectors                 |
| 1.1.0   | Error codes instead of i18n in library |
| 1.2.0   | Spec + vectors in `docs/crypto/`       |

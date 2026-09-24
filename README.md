# pear-crypt

Client-side encryption: master key wrap, file blobs, metadata, share envelopes.

MIT License — see [LICENSE](./LICENSE).

|                  |                                                |
| ---------------- | ---------------------------------------------- |
| **Spec**         | [docs/crypto/SPEC.md](./docs/crypto/SPEC.md)   |
| **Test vectors** | [docs/crypto/vectors/](./docs/crypto/vectors/) |
| **Source**       | [src/](./src/)                                 |
| **Demo sandbox** | [pear-crypt-demo](../pear-crypt-demo/)         |

## Library

```bash
npm install
npm run typecheck
npm run lint
npm run format:check
npm test
npm run coverage
```

`npm run lint` — ESLint с типовыми проверками TypeScript. `npm run format` приводит код к Prettier: одинарные кавычки, точки с запятой, ширина строки 100. Строка переносится, только когда не помещается в эту ширину. Длинная цепочка методов при переносе продолжается со следующей строки.

`npm test` гоняет unit-тесты и контракт против закоммиченных vectors. `npm run coverage` требует не меньше 90% по строкам, веткам и функциям.

Обновить committed vectors после изменения `src/`:

```bash
npm run export:vectors
```

Публичный вход — [`src/index.ts`](./src/index.ts). Код разложен по доменам:

| Домен      | Путь                               | Что делает                                                                 |
| ---------- | ---------------------------------- | -------------------------------------------------------------------------- |
| Ключи      | [`src/keys/`](./src/keys/)         | Мастер-ключ, wrap паролем или PIN, HKDF-ключи файла, метаданных и настроек |
| Файлы      | [`src/files/`](./src/files/)       | Шифрование содержимого файла                                               |
| Метаданные | [`src/metadata/`](./src/metadata/) | Шифрование и разбор метаданных файла                                       |
| Share      | [`src/share/`](./src/share/)       | Конверт для шаринга                                                        |
| Recovery   | [`src/recovery/`](./src/recovery/) | Код восстановления и его конверт                                           |
| Demo       | [`src/demo/`](./src/demo/)         | Песочница `pk1.`                                                           |
| Кадр блоба | [`src/wire/`](./src/wire/)         | Общий формат `version \| nonce \| ciphertext`                              |

Рядом лежат общие куски: [`constants.ts`](./src/constants.ts), [`encoding.ts`](./src/encoding.ts), [`errors.ts`](./src/errors.ts).

## Demo

Интерактивная песочница — **pear-crypt-demo** (checkout рядом):

```
ws/my/
  pear-crypt/
  pear-crypt-demo/   → alias pear-crypt → ../pear-crypt/src/index.ts
```

```bash
git clone <repo-url> pear-crypt-demo
cd pear-crypt-demo
npm install && npm run dev
```

http://localhost:5175 — `encryptDemoText` / `decryptDemoText` (`pk1.` wire).

Wire-format v1 (`pear-keep-file:`, `application/x-pear-keep-e2ee-v1`, …) зафиксирован в SPEC и сохранён для совместимости с существующими ciphertext.

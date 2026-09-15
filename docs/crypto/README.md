# Спецификация и test vectors

| Файл | Назначение |
|------|------------|
| [SPEC.md](./SPEC.md) | Wire-format, KDF, AAD, threat model |
| [vectors/pear-crypt-vectors-v1.json](./vectors/pear-crypt-vectors-v1.json) | Детерминированные test vectors |

**Код:** [`../../src/`](../../src/)

Vectors закоммичены здесь; при изменении `src/`:

```bash
npm run export:vectors
```

У потребителя (pear-keep): `cd frontend && npm run export:vectors` — тот же JSON, contract test в обоих репозиториях.

**Live demo:** [pear-crypt-demo](../../../pear-crypt-demo/) — `npm install && npm run dev` (рядом нужен checkout `pear-crypt`).

**Tests:** `npm test` — unit tests + contract test против committed vectors. Обновить JSON: `npm run export:vectors`.

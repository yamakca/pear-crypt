# pear-crypt

Client-side encryption: master key wrap, file blobs, metadata, share envelopes.

| | |
|---|---|
| **Spec** | [docs/crypto/SPEC.md](./docs/crypto/SPEC.md) |
| **Test vectors** | [docs/crypto/vectors/](./docs/crypto/vectors/) |
| **Source** | [src/](./src/) |
| **Demo sandbox** | [pear-crypt-demo](../pear-crypt-demo/) |

## Library

```bash
npm install
npm run typecheck
npm test
```

Обновить committed vectors после изменения `src/`:

```bash
npm run export:vectors
```

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

# pear-crypt

Client-side encryption: master key wrap, file blobs, metadata, share envelopes.

| | |
|---|---|
| **Spec** | [docs/crypto/SPEC.md](./docs/crypto/SPEC.md) |
| **Test vectors** | [docs/crypto/vectors/](./docs/crypto/vectors/) |
| **Source** | [src/](./src/) |
| **Demo sandbox** | [pear-crypt-demo](../pear-crypt-demo/) (отдельный репозиторий) |

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

Интерактивная песочница вынесена в **pear-crypt-demo** (checkout рядом):

```bash
git clone <repo-url> pear-crypt-demo
cd pear-crypt-demo
npm install && npm run dev
```

http://localhost:5175 — `encryptDemoText` / `decryptDemoText` (`pk1.` wire).

## Consumer (pear-keep)

Checkout рядом с приложением:

```
ws/my/
  pear-crypt/
  pear-crypt-demo/
  pear-keep/    → alias @pear-keep/crypto → ../pear-crypt/src/index.ts
```

Contract test и `npm run export:vectors` в `pear-keep/frontend` используют те же vectors и builder из этого репозитория.

# Strig playground

A page where you write a policy, see its problems with line, column and hint, and ask who can do what. The engine is the real one, compiled to WebAssembly through the `strig-node` binding; nothing is simulated.

## Run it

```sh
npm ci --prefix playground    # once: the TypeScript compiler
sh playground/build.sh        # builds the wasm engine, compiles the TypeScript, assembles playground/dist/
node playground/dist-node/serve.js   # serves playground/dist/ on http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080`. The page needs HTTP, not `file://`, to load the wasm module. A different port goes as an argument: `node playground/dist-node/serve.js 9000`.

## How it is built

`build.sh` runs `crates/strig-node/scripts/build.sh wasm`, the same build the Node binding uses in CI, then compiles the TypeScript with `tsc` (no bundler) and copies the static files and the compiled browser entry of the binding (`crates/strig-node/js/dist/`) into `playground/dist/`. The page goes to `playground/dist/`; the server and the smoke test, which run in Node, go to `playground/dist-node/`. It needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` at the version the workspace pins. `playground/dist/` and `playground/dist-node/` are generated and not committed.

## Files

- `index.html`, `style.css`: the page and its tokens, see [IDENTITY.md](IDENTITY.md).
- `favicon.svg`, `favicon-32.png`: the Strig mark as the tab icon (the SVG follows the light and dark schemes).
- `app.ts`: the interface and the state kept in the URL hash (`#case=&syn=&tab=&ask=&fix=&theme=`).
- `engine.ts`: the bridge to the wasm binding (compile, convert, evaluate, canonical JSON).
- `cases.ts`: the example policies, in the three syntaxes, with the questions asked of each.
- `highlight.ts`: syntax highlighting for the editor.
- `serve.ts`: the static server for local use.
- `test/smoke.ts`: every example compiles in the three syntaxes and the engine answers every question. After the build: `npm test --prefix playground` (runs `node --test dist-node/test/smoke.js`).
- `tsconfig.json` (the page, `moduleResolution: bundler`) and `tsconfig.node.json` (server and test, `NodeNext`); `types/engine/browser.d.ts` types `./engine/browser.js`, which `build.sh` assembles in `dist/`.

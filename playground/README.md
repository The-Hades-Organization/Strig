# Strig playground

A page where you write a policy, see its problems with line, column and hint, and ask who can do what. The engine is the real one, compiled to WebAssembly through the `strig-node` binding; nothing is simulated.

## Run it

```sh
sh playground/build.sh        # builds the wasm engine and assembles playground/dist/
node playground/serve.mjs     # serves playground/dist/ on http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080`. The page needs HTTP, not `file://`, to load the wasm module. A different port goes as an argument: `node playground/serve.mjs 9000`.

## How it is built

`build.sh` runs `crates/strig-node/scripts/build.sh wasm`, the same build the Node binding uses in CI, then copies the page and the browser entry of the binding into `playground/dist/`. It needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` at the version the workspace pins. `playground/dist/` is generated and not committed.

## Files

- `index.html`, `style.css`: the page and its tokens, see [IDENTITY.md](IDENTITY.md).
- `app.js`: the interface and the state kept in the URL hash (`#case=&syn=&tab=&ask=&fix=&theme=`).
- `engine.js`: the bridge to the wasm binding (compile, convert, evaluate, canonical JSON).
- `cases.js`: the example policies, in the three syntaxes, with the questions asked of each.
- `highlight.js`: syntax highlighting for the editor.
- `serve.mjs`: the static server for local use.

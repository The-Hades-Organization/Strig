#!/usr/bin/env sh
# Builds the playground into playground/dist/: the WebAssembly engine from this workspace
# (the same build the Node binding uses) plus the static page. Needs wasm-bindgen-cli, with
# the version the workspace pins, the wasm32-unknown-unknown target and `npm ci` (or install) in
# playground/ and crates/strig-node/js/ for the TypeScript compiler.
# Output: dist/ (the page, served by dist-node/serve.js) and dist-node/ (the server and the smoke test).
# Usage: sh playground/build.sh
set -eu
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
JS="$ROOT/crates/strig-node/js"

sh "$ROOT/crates/strig-node/scripts/build.sh" wasm
(cd "$JS" && npm run build:ts)

rm -rf dist dist-node
npm run build:ts
mkdir -p dist/engine dist/wasm
cp index.html style.css favicon.svg favicon-32.png dist/
cp "$JS/dist/browser.js" "$JS/dist/dsl.js" "$JS/dist/fast.js" "$JS/dist/protocol.js" dist/engine/
cp "$JS/wasm/strig.js" "$JS/wasm/strig_bg.wasm" dist/wasm/
echo "playground built in playground/dist/"

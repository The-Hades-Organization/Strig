#!/usr/bin/env sh
# Builds the playground into playground/dist/: the WebAssembly engine from this workspace
# (the same build the Node binding uses) plus the static page. Needs wasm-bindgen-cli, with
# the version the workspace pins, and the wasm32-unknown-unknown target.
# Usage: sh playground/build.sh
set -eu
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
JS="$ROOT/crates/strig-node/js"

sh "$ROOT/crates/strig-node/scripts/build.sh" wasm

rm -rf dist
mkdir -p dist/engine/wasm
cp index.html style.css app.js cases.js engine.js highlight.js dist/
cp "$JS/browser.js" "$JS/dsl.js" "$JS/protocol.js" dist/engine/
cp "$JS/wasm/strig.js" "$JS/wasm/strig_bg.wasm" dist/engine/wasm/
echo "playground built in playground/dist/"

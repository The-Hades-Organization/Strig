#!/usr/bin/env sh
# Gera js/native/themis.<plataforma>-<arch>.node (Node e Bun) e js/wasm/ (navegador e fallback).
# Uso: scripts/build.sh [native|wasm|all]   (padrão: all)
set -eu
cd "$(dirname "$0")/.."
TARGET_DIR="${CARGO_TARGET_DIR:-$(cd ../.. && pwd)/target}"
WHAT="${1:-all}"

if [ "$WHAT" = all ] || [ "$WHAT" = native ]; then
  cargo build -p themis-node --features napi --release
  PLATFORM="$(node -p 'process.platform + "-" + process.arch')"
  case "$(uname -s)" in
    Darwin) LIB=libthemis_node.dylib ;;
    MINGW*|MSYS*|CYGWIN*) LIB=themis_node.dll ;;
    *) LIB=libthemis_node.so ;;
  esac
  mkdir -p js/native
  cp "$TARGET_DIR/release/$LIB" "js/native/themis.$PLATFORM.node"
fi

if [ "$WHAT" = all ] || [ "$WHAT" = wasm ]; then
  cargo build -p themis-node --features wasm --release --target wasm32-unknown-unknown
  wasm-bindgen --target web --out-dir js/wasm --out-name themis \
    "$TARGET_DIR/wasm32-unknown-unknown/release/themis_node.wasm"
fi

#!/bin/sh
# Builds the C-ABI WebAssembly module (crates/strig-wasi) and places it where the Go and JVM
# bindings read it:
#   bindings/jvm/wasm/strig.wasm       the jar resource (ignored by git, built in CI)
#   bindings/go/strig.wasm.gz          the go:embed file (committed: a Go module is its own tag)
#   bindings/go/strig.wasm.stamp       hash of the sources the committed module was built from
#
# sh bindings/scripts/build-wasi.sh          build and refresh everything
# sh bindings/scripts/build-wasi.sh jvm      build and refresh only the jar resource (CI)
# sh bindings/scripts/build-wasi.sh check    fail if the committed Go module is older than its sources
set -eu
cd "$(dirname "$0")/../.."

stamp() {
  git ls-files crates/strig crates/strig-node/src crates/strig-wasi Cargo.lock \
    | LC_ALL=C sort | xargs cat | sha256sum | cut -d' ' -f1
}

mode="${1:-all}"

if [ "$mode" = check ]; then
  if [ "$(stamp)" != "$(cat bindings/go/strig.wasm.stamp)" ]; then
    echo "bindings/go/strig.wasm.gz was built from older sources: run sh bindings/scripts/build-wasi.sh and commit" >&2
    exit 1
  fi
  exit 0
fi

cargo build -p strig-wasi --target wasm32-unknown-unknown --release
wasm="${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/strig_wasi.wasm"

mkdir -p bindings/jvm/wasm
cp "$wasm" bindings/jvm/wasm/strig.wasm

if [ "$mode" = all ]; then
  gzip -9 -n -c "$wasm" > bindings/go/strig.wasm.gz
  stamp > bindings/go/strig.wasm.stamp
fi

#!/bin/sh
# Runs one fuzz target for a while: ./fuzz/run.sh <target> [seconds]. Needs nightly and cargo-fuzz.
set -eu
target="${1:?usage: run.sh <target> [seconds]}"
seconds="${2:-60}"
cd "$(dirname "$0")"
case "$target" in
  dsl_parse | dsl_format | dsl_convert) seeds=seeds/dsl; dict="-dict=dictionaries/dsl.dict" ;;
  *) seeds="seeds/$target"; dict="" ;;
esac
mkdir -p "corpus/$target"
# shellcheck disable=SC2086
exec cargo +nightly fuzz run "$target" "corpus/$target" "$seeds" -- -max_total_time="$seconds" -max_len=65536 $dict

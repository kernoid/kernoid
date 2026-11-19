#!/bin/sh
# SPDX-License-Identifier: MIT
# Builds the vaults for the web app: WebAssembly and its JavaScript bindings into web/vault/dist (@kernoid/vault).
# Besides what kit/e2e/scripts/build-wasm.sh needs, SQLite is compiled for the browser (sqlite-wasm-rs): a clang that
# knows wasm32 and an llvm-ar – Apple's ar writes no WebAssembly objects. Taken from AR_wasm32_unknown_unknown and
# CC_wasm32_unknown_unknown if set, else llvm-ar and clang on the PATH or Homebrew's LLVM.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out="$here/../../web/vault/dist"
pick() {
  for candidate in "$@"; do
    if command -v "$candidate" >/dev/null 2>&1; then command -v "$candidate"; return; fi
  done
  echo "none of $* found" >&2
  exit 1
}
llvm=/opt/homebrew/opt/llvm/bin
if [ "$(uname)" = Darwin ]; then
  : "${AR_wasm32_unknown_unknown:=$(pick "$llvm/llvm-ar" llvm-ar)}"
  : "${CC_wasm32_unknown_unknown:=$(pick "$llvm/clang" clang)}"
else
  : "${AR_wasm32_unknown_unknown:=$(pick llvm-ar llvm-ar-19 llvm-ar-18)}"
  : "${CC_wasm32_unknown_unknown:=$(pick clang clang-19 clang-18)}"
fi
export AR_wasm32_unknown_unknown CC_wasm32_unknown_unknown
cargo build --manifest-path "$here/Cargo.toml" --locked --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm
rm -rf "$out"
wasm-bindgen --target web --out-dir "$out" --out-name kernoid_vault \
  "$here/../target/wasm32-unknown-unknown/release/kernoid_vault.wasm"

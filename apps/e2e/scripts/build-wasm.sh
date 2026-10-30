#!/bin/sh
# SPDX-License-Identifier: MIT
# Builds the end-to-end library for the web app: WebAssembly and its JavaScript bindings into web/e2e/dist
# (@kernoid/e2e). Needs the target wasm32-unknown-unknown (rust-toolchain.toml) and wasm-bindgen-cli of the same
# version as the crate wasm-bindgen in Cargo.lock:
#   cargo install wasm-bindgen-cli --version "$(scripts/wasm-bindgen-version.sh)" --locked
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out="$here/../../web/e2e/dist"
cargo build --manifest-path "$here/Cargo.toml" --locked --release --target wasm32-unknown-unknown --features wasm
rm -rf "$out"
wasm-bindgen --target web --out-dir "$out" --out-name kernoid_e2e \
  "$here/target/wasm32-unknown-unknown/release/kernoid_e2e.wasm"

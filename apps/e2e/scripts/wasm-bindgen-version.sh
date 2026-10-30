#!/bin/sh
# SPDX-License-Identifier: MIT
# The version of wasm-bindgen in Cargo.lock – wasm-bindgen-cli must be the same.
sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p;}' "$(dirname "$0")/../Cargo.lock"

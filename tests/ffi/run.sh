#!/usr/bin/env bash
# Builds the C library and runs the C smoke test against it.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build -p sybau-ffi
out=target/ffi-smoke
mkdir -p "$out"
${CC:-cc} -Wall -Wextra -Werror -Iinclude tests/ffi/smoke.c -Ltarget/debug -lsybaucore -o "$out/smoke"
LD_LIBRARY_PATH=target/debug "$out/smoke" "${1:-20811}"

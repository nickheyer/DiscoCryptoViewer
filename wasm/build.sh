#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENGINE_DIR="$SCRIPT_DIR/engine"
OUT_DIR="$PROJECT_ROOT/dist/wasm"

mkdir -p "$OUT_DIR"

echo "==> Compiling Go WASM engine..."
cd "$ENGINE_DIR"
GOOS=js GOARCH=wasm go build -o "$OUT_DIR/engine.wasm" .

echo "==> Copying wasm_exec.js glue..."
GOROOT=$(go env GOROOT)
cp "$GOROOT/lib/wasm/wasm_exec.js" "$OUT_DIR/wasm_exec.js"

echo "==> WASM build complete: $OUT_DIR"
ls -lh "$OUT_DIR"

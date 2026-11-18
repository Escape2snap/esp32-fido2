#!/usr/bin/env bash
# Local preflight checks (there is no GitHub Actions CI).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v idf.py >/dev/null 2>&1; then
    echo "idf.py not found. Please source your ESP-IDF export.sh first." >&2
    exit 2
fi

echo "== build =="
idf.py build
echo "== Ed25519 constant-time gate =="
./tools/check-eddsa-ct.sh
echo "== whitespace check =="
git diff --check
echo "preflight OK"

#!/usr/bin/env bash
# Fetch the pinned third-party sources required by esp32-fido2.
# third-party/ is gitignored; this script makes a checkout reproducible.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p third-party

TINYCBOR_URL="https://github.com/intel/tinycbor.git"
TINYCBOR_COMMIT="9441b2ca882f95849c93de03f2c754196db13154"
MBEDTLS_URL="https://github.com/polhenarejos/mbedtls.git"
MBEDTLS_BRANCH="mbedtls-3.6-eddsa"
MBEDTLS_COMMIT="68aafa5e51ce55c88027ed8b7a02934baba7a984"

checkout() {
    dir=$1
    commit=$2
    if ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
        git -C "$dir" fetch origin "$commit"
    fi
    git -C "$dir" checkout --detach "$commit"
}

if [ ! -d third-party/tinycbor/.git ]; then
    git clone "$TINYCBOR_URL" third-party/tinycbor
fi
checkout third-party/tinycbor "$TINYCBOR_COMMIT"

# tinycbor needs the generated export/version headers.
if [ ! -f third-party/tinycbor/src/tinycbor-export.h ]; then
    cp third-party/tinycbor/src/tinycbor-export.h.in third-party/tinycbor/src/tinycbor-export.h
fi
if [ ! -f third-party/tinycbor/src/tinycbor-version.h ]; then
    cat > third-party/tinycbor/src/tinycbor-version.h <<'EOF'
#define TINYCBOR_VERSION_MAJOR 7
#define TINYCBOR_VERSION_MINOR 0
#define TINYCBOR_VERSION_PATCH 0
EOF
fi

if [ ! -d third-party/mbedtls-fork/.git ]; then
    git clone --branch "$MBEDTLS_BRANCH" "$MBEDTLS_URL" third-party/mbedtls-fork
fi
checkout third-party/mbedtls-fork "$MBEDTLS_COMMIT"
git -C third-party/mbedtls-fork submodule update --init --depth 1

# The fork enables Ed448 by default, but this firmware only needs Ed25519 and
# does not configure SHA-3; the local patch turns Ed448 off.
if grep -q '^#define MBEDTLS_ECP_DP_ED448_ENABLED' third-party/mbedtls-fork/include/mbedtls/mbedtls_config.h; then
    git -C third-party/mbedtls-fork apply "$ROOT/tools/patches/mbedtls-ed448-off.patch"
fi

echo "third-party dependencies are ready (tinycbor $TINYCBOR_COMMIT, mbedtls $MBEDTLS_COMMIT)"

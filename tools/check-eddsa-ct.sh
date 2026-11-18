#!/usr/bin/env bash
# Guard the Ed25519 constant-time property against compiler changes.
# See components/eddsa/CMakeLists.txt: the three files are compiled with -O3,
# but a CMake change could silently drop it, so also check the machine code.
set -eo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OBJ_DIR="$ROOT/build/esp-idf/eddsa/CMakeFiles/__idf_eddsa.dir"
OD=$XTENSA_OBJDUMP
if [ -z "$OD" ]; then
    if command -v xtensa-esp32s3-elf-objdump >/dev/null 2>&1; then
        OD=xtensa-esp32s3-elf-objdump
    else
        OD=$(ls "$HOME"/.espressif/tools/xtensa-esp-elf/*/xtensa-esp-elf/bin/xtensa-esp32s3-elf-objdump 2>/dev/null | head -n 1)
    fi
fi
if [ -z "$OD" ]; then
    echo "xtensa objdump not found; export XTENSA_OBJDUMP or run 'idf.py export'" >&2
    exit 2
fi
if [ ! -d "$OBJ_DIR" ]; then
    echo "build objects not found; run 'idf.py build' first" >&2
    exit 2
fi

fail=0
check() {
    file=$1
    fn=$2
    limit=$3
    obj="$OBJ_DIR/$file"
    if ! "$OD" -d "$obj" | grep -q "<$fn>:"; then
        echo "MISSING $fn in $file" >&2
        fail=1
        return
    fi
    n=$("$OD" -d "$obj" | awk -v fn="$fn" '
        $0 ~ "^[0-9a-f]+ <" fn ">:" { inside=1; next }
        inside && $0 ~ "^[0-9a-f]+ <" { inside=0 }
        inside && $0 ~ /[[:space:]](beq|bne|blt|bltu|bge|bgeu|beqz|bnez|bgez|bltz|bbc|bbs|bnone|bany|ball|balt|bnall|loop|loopnez|loopgtz)[[:space:]]/ { n++ }
        END { print n+0 }
    ')
    if [ "$n" -gt "$limit" ]; then
        echo "FAIL $fn: $n conditional branches (limit $limit)" >&2
        fail=1
    else
        echo "ok   $fn: $n conditional branches (limit $limit)"
    fi
}

check fe25519.c.obj fe25519_sub 0
check fe25519.c.obj fe25519_add 0
check fe25519.c.obj fe25519_cmov 0
check fe25519.c.obj fe25519_mul 2
check fe25519.c.obj fe25519_invert 4
check sc25519.c.obj ed25519_sc_reduce 0
check sc25519.c.obj ed25519_sc_muladd 0
check eddsa_ecp_extras.c.obj scalarmult_base 4

exit "$fail"

#!/bin/sh
# Builds a guest test program without the NDK: clang and lld against bionic's libc.so from the
# extracted system image, precompiled with amc and signed.
#
#   tests/guest/build.sh <name> <datadir>    -> <datadir>/data/local/tmp/<name>
#   build/amrun -r build/root -d <datadir> /data/local/tmp/<name>
#
# WORK is the extracted image (README step 1), default ./work of the main checkout.
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
name=$1 data=$2
[ -n "$name" ] && [ -n "$data" ] || { sed -n 2,7p "$0"; exit 2; }
WORK=${WORK:-$repo/work}
[ -d "$WORK" ] || WORK=$HOME/src/andromach/work
libc=$WORK/fs/apex/com.android.runtime/lib64/bionic/libc.so
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
clang --target=aarch64-linux-android35 -fPIE -O1 -mno-outline-atomics -ffreestanding -fno-builtin \
    -Wno-incompatible-library-redeclaration -c "$here/crt.S" -o "$out/crt.o"
clang --target=aarch64-linux-android35 -fPIE -O1 -mno-outline-atomics -ffreestanding -fno-builtin \
    -Wno-incompatible-library-redeclaration -c "$here/$name.c" -o "$out/$name.o"
ld.lld -pie -z max-page-size=16384 --dynamic-linker /system/bin/linker64 -o "$out/$name" "$out/crt.o" "$out/$name.o" "$libc"
mkdir -p "$data/data/local/tmp"
python3 "$repo/tools/amc.py" --platform macos "$out/$name" "$data/data/local/tmp/$name" >/dev/null
codesign -s - -f "$data/data/local/tmp/$name" 2>/dev/null

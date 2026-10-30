#!/bin/sh
# Unpack every APEX under <system-root>/system/apex into <out>/<apex-name>, which is where
# Android mounts them at runtime (/apex/<name>). Needs unzip, fsck.erofs (brew erofs-utils) and
# debugfs (brew e2fsprogs).
#   extract_apex.sh <system-root> <out>
set -eu
root=$1; out=$2
tmp=$(mktemp -d)
for a in "$root"/system/apex/*.apex "$root"/system/apex/*.capex; do
    [ -f "$a" ] || continue
    rm -rf "$tmp"/*
    unzip -qo "$a" -d "$tmp"
    if [ -f "$tmp/original_apex" ]; then   # compressed APEX wraps the real one
        mv "$tmp/original_apex" "$tmp/inner.apex"; unzip -qo "$tmp/inner.apex" -d "$tmp"
    fi
    # apex_manifest.pb: field 1 is the name (tag 0x0a, one-byte length)
    name=$(python3 -c "import sys;b=open(sys.argv[1],'rb').read();assert b[0]==10;print(b[2:2+b[1]].decode())" "$tmp/apex_manifest.pb")
    rm -rf "$out/$name"; mkdir -p "$out/$name"
    # payloads are EROFS, or ext4 in older APEXes (superblock magic 0xEF53 at 1080)
    if [ "$(xxd -s 1080 -l 2 -p "$tmp/apex_payload.img")" = 53ef ]; then
        "$(brew --prefix e2fsprogs)/sbin/debugfs" -R "rdump / $out/$name" "$tmp/apex_payload.img" 2>/dev/null
    else
        fsck.erofs --extract="$out/$name" --no-preserve "$tmp/apex_payload.img" >/dev/null
    fi
    echo "$name"
done
rm -rf "$tmp"

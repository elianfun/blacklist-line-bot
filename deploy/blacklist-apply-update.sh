#!/bin/bash
# Applies a staged ip.txt to the HFS-served blacklist directory.
# Installed at /usr/local/sbin/blacklist-apply-update.sh, root:root 755.
# Invoked via: sudo /usr/local/sbin/blacklist-apply-update.sh (no args, no shell metacharacters accepted)
set -euo pipefail

SRC="/home/inno/blacklist-bot/staging/ip.txt"
DST="/home/inno/hfs/share/blacklist/ip.txt"

if [ ! -f "$SRC" ]; then
    echo "staging file not found: $SRC" >&2
    exit 1
fi

if [ ! -s "$SRC" ]; then
    echo "staging file is empty, refusing to apply: $SRC" >&2
    exit 1
fi

cp "$SRC" "$DST"
chown root:root "$DST"
chmod 644 "$DST"
echo "updated $DST ($(wc -l < "$DST") lines)"

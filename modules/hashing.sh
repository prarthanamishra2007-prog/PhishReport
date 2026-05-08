#!/bin/bash
# ─────────────────────────────────────────
# MODULE: hashing.sh
# Computes SHA-256, SHA-1, MD5 for a file
# ─────────────────────────────────────────

compute_hashes() {
    local filepath="$1"

    if [[ ! -f "$filepath" ]]; then
        echo "[ERROR] File not found: $filepath"
        return 1
    fi

    HASH_SHA256=$(sha256sum "$filepath" | awk '{print $1}')
    HASH_SHA1=$(sha1sum   "$filepath" | awk '{print $1}')
    HASH_MD5=$(md5sum     "$filepath" | awk '{print $1}')

    echo "[HASH] SHA-256 : $HASH_SHA256"
    echo "[HASH] SHA-1   : $HASH_SHA1"
    echo "[HASH] MD5     : $HASH_MD5"
}

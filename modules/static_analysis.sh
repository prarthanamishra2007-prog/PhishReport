#!/bin/bash
# ─────────────────────────────────────────
# MODULE: static_analysis.sh
# File type detection + strings analysis
# ─────────────────────────────────────────

run_static_analysis() {
    local filepath="$1"

    echo "[STATIC] Running file type detection..."
    FILE_TYPE=$(file -b "$filepath" 2>/dev/null)
    FILE_SIZE=$(du -sh "$filepath" 2>/dev/null | awk '{print $1}')
    echo "[STATIC] Type : $FILE_TYPE"
    echo "[STATIC] Size : $FILE_SIZE"

    echo "[STATIC] Extracting suspicious strings..."

    # URLs and domains
    STRINGS_URLS=$(strings "$filepath" 2>/dev/null \
        | grep -iE 'https?://[^ ]{6,}' \
        | sort -u | head -20)

    # Suspicious keywords often found in malware
    STRINGS_KEYWORDS=$(strings "$filepath" 2>/dev/null \
        | grep -iE 'cmd\.exe|powershell|base64|wget|curl|eval|exec|payload|shell|backdoor|keylog|inject|bypass|obfuscat|decrypt|dropper|loader|reverse|connect|socket|bind|listen|upload|download|credential|password|token|registry|HKEY|startup|autorun|persistence' \
        | sort -u | head -30)

    # Email addresses found inside
    STRINGS_EMAILS=$(strings "$filepath" 2>/dev/null \
        | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
        | sort -u | head -10)

    # Domain names
    STRINGS_DOMAINS=$(strings "$filepath" 2>/dev/null \
        | grep -oE '\b([a-zA-Z0-9-]+\.){1,3}(com|net|org|io|ru|cn|tk|pw|xyz|top|cc|info|biz)\b' \
        | grep -v '^\.' | sort -u | head -20)

    # Summary counts
    local url_count kw_count email_count domain_count
    url_count=$(echo "$STRINGS_URLS"    | grep -c . || echo 0)
    kw_count=$(echo "$STRINGS_KEYWORDS" | grep -c . || echo 0)
    email_count=$(echo "$STRINGS_EMAILS" | grep -c . || echo 0)
    domain_count=$(echo "$STRINGS_DOMAINS" | grep -c . || echo 0)

    echo "[STATIC] URLs found      : $url_count"
    echo "[STATIC] Suspicious kw   : $kw_count"
    echo "[STATIC] Emails found    : $email_count"
    echo "[STATIC] Domains found   : $domain_count"

    # Risk flag
    if [[ "$kw_count" -ge 5 ]]; then
        STATIC_RISK="HIGH — many suspicious indicators in strings"
    elif [[ "$kw_count" -ge 2 ]]; then
        STATIC_RISK="MEDIUM — some suspicious strings present"
    else
        STATIC_RISK="LOW — few suspicious strings detected"
    fi
    echo "[STATIC] Static risk     : $STATIC_RISK"
}

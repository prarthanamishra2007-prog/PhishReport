#!/bin/bash
# ─────────────────────────────────────────
# MODULE: virustotal.sh
# Submits hash to VT API, parses results
# ─────────────────────────────────────────

query_virustotal() {
    local hash="$1"
    local api_key="$2"

    echo "[VT] Querying VirusTotal for hash: $hash"

    local response
    response=$(curl -s --request GET \
        --url "https://www.virustotal.com/api/v3/files/${hash}" \
        --header "x-apikey: ${api_key}")

    # Check for errors
    local error
    error=$(echo "$response" | jq -r '.error.message // empty')
    if [[ -n "$error" ]]; then
        echo "[VT] API Error: $error"
        VT_VERDICT="Unknown (API error: $error)"
        VT_ENGINES_FLAGGED="N/A"
        VT_MALWARE_NAME="N/A"
        VT_FIRST_SEEN="N/A"
        VT_LINK="https://www.virustotal.com/gui/file/${hash}"
        return 1
    fi

    # Parse fields
    VT_ENGINES_FLAGGED=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    VT_ENGINES_TOTAL=$(echo "$response"   | jq -r '([.data.attributes.last_analysis_stats | to_entries[].value] | add) // 0')
    VT_MALWARE_NAME=$(echo "$response"    | jq -r '.data.attributes.popular_threat_classification.suggested_threat_label // "Unknown"')
    VT_FIRST_SEEN_RAW=$(echo "$response"  | jq -r '.data.attributes.first_submission_date // empty')
    VT_LINK="https://www.virustotal.com/gui/file/${hash}"

    # Convert epoch to human date
    if [[ -n "$VT_FIRST_SEEN_RAW" && "$VT_FIRST_SEEN_RAW" != "null" ]]; then
        VT_FIRST_SEEN=$(date -d "@${VT_FIRST_SEEN_RAW}" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo "$VT_FIRST_SEEN_RAW")
    else
        VT_FIRST_SEEN="Not seen before (new sample)"
    fi

    # Determine verdict
    if [[ "$VT_ENGINES_FLAGGED" -ge 10 ]]; then
        VT_VERDICT="MALICIOUS"
    elif [[ "$VT_ENGINES_FLAGGED" -ge 3 ]]; then
        VT_VERDICT="SUSPICIOUS"
    elif [[ "$VT_ENGINES_FLAGGED" -ge 1 ]]; then
        VT_VERDICT="LOW RISK"
    else
        VT_VERDICT="CLEAN (0 detections)"
    fi

    echo "[VT] Engines flagged : $VT_ENGINES_FLAGGED / $VT_ENGINES_TOTAL"
    echo "[VT] Malware name    : $VT_MALWARE_NAME"
    echo "[VT] First seen      : $VT_FIRST_SEEN"
    echo "[VT] Verdict         : $VT_VERDICT"
    echo "[VT] Report link     : $VT_LINK"
}

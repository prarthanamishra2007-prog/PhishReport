#!/bin/bash
# ─────────────────────────────────────────
# MODULE: geoip.sh
# Extracts IPs from strings output, geolocates via ip-api.com
# ─────────────────────────────────────────

lookup_geoip() {
    local filepath="$1"

    echo "[GEO] Extracting IPs from file strings..."

    # Pull printable strings, grep for IPv4 addresses, deduplicate
    local ips
    ips=$(strings "$filepath" 2>/dev/null \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        | sort -u \
        | grep -vE '^(127\.|0\.|255\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') 

    if [[ -z "$ips" ]]; then
        echo "[GEO] No external IPs found in file."
        GEO_RESULTS="No external IP addresses detected in file."
        return
    fi

    GEO_RESULTS=""
    while IFS= read -r ip; do
        echo "[GEO] Looking up: $ip"
        local geo
        geo=$(curl -s "http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,query")
        
        local status
        status=$(echo "$geo" | jq -r '.status')

        if [[ "$status" == "success" ]]; then
            local country city isp org
            country=$(echo "$geo" | jq -r '.country')
            city=$(echo    "$geo" | jq -r '.city')
            isp=$(echo     "$geo" | jq -r '.isp')
            org=$(echo     "$geo" | jq -r '.org')
            GEO_RESULTS+="  IP: $ip | Location: $city, $country | ISP: $isp | Org: $org\n"
            echo "[GEO] $ip → $city, $country ($isp)"
        else
            GEO_RESULTS+="  IP: $ip | GeoIP lookup failed\n"
        fi

        sleep 0.5  # ip-api.com rate limit: 45 req/min on free tier
    done <<< "$ips"
}

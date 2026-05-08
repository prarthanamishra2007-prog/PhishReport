#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║              P H I S H   R E P O R T   v1.0                    ║
# ║     Automated Phishing / Malware Analysis Report Generator      ║
# ╚══════════════════════════════════════════════════════════════════╝

# ── Paths ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/.phishreport_config"
REPORTS_DIR="${SCRIPT_DIR}/reports"
MODULES_DIR="${SCRIPT_DIR}/modules"

# ── Colours ───────────────────────────────────────────────────────
RED='\033[0;31m';  YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m';      RESET='\033[0m'

# ── Source modules ────────────────────────────────────────────────
source "${MODULES_DIR}/hashing.sh"
source "${MODULES_DIR}/virustotal.sh"
source "${MODULES_DIR}/geoip.sh"
source "${MODULES_DIR}/static_analysis.sh"
source "${MODULES_DIR}/report.sh"

# ══════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗"
    echo "  ██╔══██╗██║  ██║██║██╔════╝██║  ██║"
    echo "  ██████╔╝███████║██║███████╗███████║"
    echo "  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║"
    echo "  ██║     ██║  ██║██║███████║██║  ██║"
    echo "  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝"
    echo ""
    echo "   ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗"
    echo "   ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝"
    echo "   ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║   "
    echo "   ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   "
    echo "   ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║   "
    echo "   ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
    echo -e "${RESET}"
    echo -e "  ${BOLD}Automated Phishing / Malware Analysis  v1.0${RESET}"
    echo -e "  ─────────────────────────────────────────────────"
    echo ""
}

# ══════════════════════════════════════════════════════════════════
# STEP COUNTER (visual progress)
# ══════════════════════════════════════════════════════════════════
STEP=0
step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${CYAN}${BOLD}[STEP $STEP] $1${RESET}"
    echo -e "${CYAN}$(printf '─%.0s' {1..55})${RESET}"
}

# ══════════════════════════════════════════════════════════════════
# ONE-TIME CONFIG (analyst name + VT API key)
# ══════════════════════════════════════════════════════════════════
load_or_create_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        echo -e "${GREEN}[CONFIG] Loaded saved config for analyst: ${BOLD}${ANALYST_NAME}${RESET}"
    else
        echo -e "${YELLOW}${BOLD}First-time setup — this is saved and never asked again.${RESET}"
        echo ""

        read -rp "  👤 Your analyst name       : " ANALYST_NAME
        while [[ -z "$ANALYST_NAME" ]]; do
            echo -e "  ${RED}Name cannot be empty.${RESET}"
            read -rp "  👤 Your analyst name       : " ANALYST_NAME
        done

        read -rp "  🔑 VirusTotal API key      : " VT_API_KEY
        while [[ -z "$VT_API_KEY" ]]; do
            echo -e "  ${RED}API key cannot be empty.${RESET}"
            read -rp "  🔑 VirusTotal API key      : " VT_API_KEY
        done

        # Save config
        cat > "$CONFIG_FILE" <<EOF
ANALYST_NAME="${ANALYST_NAME}"
VT_API_KEY="${VT_API_KEY}"
EOF
        chmod 600 "$CONFIG_FILE"   # only owner can read (protects API key)
        echo -e "${GREEN}[CONFIG] Saved to ${CONFIG_FILE}${RESET}"
    fi
}

# ══════════════════════════════════════════════════════════════════
# PER-SCAN QUESTIONS
# ══════════════════════════════════════════════════════════════════
collect_scan_inputs() {
    # Q3: File path
    echo ""
    read -rp "  📁 Path to suspicious file : " SAMPLE_PATH
    while [[ ! -f "$SAMPLE_PATH" ]]; do
        echo -e "  ${RED}File not found. Try again.${RESET}"
        read -rp "  📁 Path to suspicious file : " SAMPLE_PATH
    done
    SAMPLE_FILENAME=$(basename "$SAMPLE_PATH")

    # Q4: Source
    echo ""
    echo "  📌 Where did this file come from?"
    echo "     1) Phishing email"
    echo "     2) Suspicious download"
    echo "     3) USB / removable media"
    echo "     4) Other"
    read -rp "  Enter choice [1-4]: " SOURCE_CHOICE
    case "$SOURCE_CHOICE" in
        1) SOURCE_LABEL="Phishing Email" ;;
        2) SOURCE_LABEL="Suspicious Download" ;;
        3) SOURCE_LABEL="USB / Removable Media" ;;
        *) SOURCE_LABEL="Other / Unknown" ;;
    esac

    # Q5: Sender (optional)
    echo ""
    read -rp "  ✉️  Sender email (Enter to skip): " SENDER_EMAIL

    # Q6: Subject (optional)
    read -rp "  📧 Email subject (Enter to skip): " EMAIL_SUBJECT

    # Auto date
    SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S %Z')
}

# ══════════════════════════════════════════════════════════════════
# CONFIRMATION BEFORE SCAN
# ══════════════════════════════════════════════════════════════════
confirm_scan() {
    echo ""
    echo -e "${BOLD}  ── Scan Summary ────────────────────────────────${RESET}"
    echo "  Analyst  : $ANALYST_NAME"
    echo "  File     : $SAMPLE_PATH"
    echo "  Source   : $SOURCE_LABEL"
    [[ -n "$SENDER_EMAIL" ]] && echo "  Sender   : $SENDER_EMAIL"
    [[ -n "$EMAIL_SUBJECT" ]] && echo "  Subject  : $EMAIL_SUBJECT"
    echo -e "${BOLD}  ─────────────────────────────────────────────────${RESET}"
    echo ""
    read -rp "  ▶  Start scan? [Y/n]: " confirm
    if [[ "${confirm,,}" == "n" ]]; then
        echo "Scan cancelled."
        exit 0
    fi
}

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
main() {
    print_banner
    load_or_create_config

    step "Collecting scan information"
    collect_scan_inputs

    confirm_scan

    step "Computing file hashes"
    compute_hashes "$SAMPLE_PATH"

    step "Running static analysis (strings, file type)"
    run_static_analysis "$SAMPLE_PATH"

    step "Querying VirusTotal API"
    query_virustotal "$HASH_SHA256" "$VT_API_KEY"

    step "GeoIP lookup on embedded IPs"
    lookup_geoip "$SAMPLE_PATH"

    step "Generating reports"
    generate_report "$REPORTS_DIR"

    # ── Final summary ─────────────────────────────────────────────
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗"
    echo -e "║          ✅  SCAN COMPLETE                       ║"
    echo -e "╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${BOLD}Verdict  :${RESET} ${RED}${VT_VERDICT}${RESET}"
    echo -e "  ${BOLD}Engines  :${RESET} ${VT_ENGINES_FLAGGED}/${VT_ENGINES_TOTAL} flagged"
    echo -e "  ${BOLD}Malware  :${RESET} ${VT_MALWARE_NAME}"
    echo -e "  ${BOLD}Risk     :${RESET} ${STATIC_RISK}"
    echo ""
    echo -e "  ${BOLD}TXT  →${RESET} ${TXT_REPORT}"
    echo -e "  ${BOLD}HTML →${RESET} ${HTML_REPORT}"
    echo ""
    echo -e "  Open the HTML report in a browser for a formatted view."
    echo ""
}

main "$@"

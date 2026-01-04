#!/bin/bash

# modules/secure-vps/standalone.sh
# Runnable entrypoint for standalone usage

# Resolve absolute path to module root
MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load Libraries
source "$MODULE_ROOT/lib/common.sh"
source "$MODULE_ROOT/lib/network.sh"
source "$MODULE_ROOT/scanners/internal.sh"
source "$MODULE_ROOT/scanners/external.sh"

# Header
echo -e "${C_BOLD}Secure-VPS Standalone Scanner${C_RESET}"
echo "======================================"

# Track Counts via simple grep/awk after run? 
# Or better, override the function locally too.

# Globals for standalone counts
COUNT_CRITICAL=0
COUNT_HIGH=0
COUNT_MEDIUM=0
COUNT_LOW=0
COUNT_INFO=0

# Override add_vps_finding for standalone fancy output & tracking
add_vps_finding() {
    local id="$1"
    local severity="$2"
    local type="$3"
    local origin="$4"
    local category="$5"
    local title="$6"
    local description="$7"
    local evidence="$8"
    local remediation="$9"

    case "$severity" in
        "$SEV_CRITICAL") ((COUNT_CRITICAL++)) ;;
        "$SEV_HIGH") ((COUNT_HIGH++)) ;;
        "$SEV_MEDIUM") ((COUNT_MEDIUM++)) ;;
        "$SEV_LOW") ((COUNT_LOW++)) ;;
        "$SEV_INFO") ((COUNT_INFO++)) ;;
    esac

    # Print nicely
    local color="$C_RESET"
    case "$severity" in
        "$SEV_CRITICAL") color="$C_RED" ;;
        "$SEV_HIGH") color="$C_RED" ;;
        "$SEV_MEDIUM") color="$C_YELLOW" ;;
        "$SEV_LOW") color="$C_BLUE" ;;
        "$SEV_INFO") color="$C_RESET" ;;
    esac

    echo -e "${color}[${severity}]${C_RESET} ${C_BOLD}${title}${C_RESET} (${id})"
    echo -e "      Category: $category | Type: $type | Origin: $origin"
    echo -e "      ${C_BOLD}Desc:${C_RESET} $description"
    if [[ -n "$evidence" ]]; then
        echo -e "      ${C_BOLD}Evidence:${C_RESET} $evidence"
    fi
     if [[ -n "$remediation" ]]; then
        echo -e "      ${C_BOLD}Fix:${C_RESET} $remediation"
    fi
    echo ""
}

# Run Scans
scan_internal
scan_external

echo "======================================"
echo -e "${C_BOLD}Scan Summary:${C_RESET}"
echo -e "${C_RED}Critical: $COUNT_CRITICAL${C_RESET}"
echo -e "${C_RED}High:     $COUNT_HIGH${C_RESET}"
echo -e "${C_YELLOW}Medium:   $COUNT_MEDIUM${C_RESET}"
echo -e "${C_BLUE}Low:      $COUNT_LOW${C_RESET}"
echo -e "Info:     $COUNT_INFO"
echo "======================================"

if (( COUNT_CRITICAL > 0 )) || (( COUNT_HIGH > 0 )); then
    echo -e "${C_RED}Result: FAILED (Critical/High findings detected)${C_RESET}"
    exit 1
elif (( COUNT_MEDIUM > 0 )); then
    echo -e "${C_YELLOW}Result: PASSED WITH WARNINGS (Medium findings detected)${C_RESET}"
    exit 0
else
    echo -e "${C_GREEN}Result: PASSED${C_RESET}"
    exit 0
fi

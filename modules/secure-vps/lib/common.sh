#!/bin/bash

# modules/secure-vps/lib/common.sh
# Shared logic and data models for secure-vps module

# --- Colors & Styles ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_BOLD='\033[1m'

# --- Enums ---
# Types: Misconfiguration, Risk Exposure, Vulnerability
TYPE_MISCONFIG="Misconfiguration"
TYPE_RISK="Risk Exposure"
TYPE_VULN="Vulnerability"

# Origins: Internal (Host), External (Network)
ORIGIN_INTERNAL="Internal"
ORIGIN_EXTERNAL="External"

# Severities
SEV_INFO="INFO"
SEV_LOW="LOW"
SEV_MEDIUM="MEDIUM"
SEV_HIGH="HIGH"
SEV_CRITICAL="CRITICAL"

# --- Globals ---
# JSON array to store findings for structured output
FINDINGS_JSON="[]"

# --- Functions ---

# Function: vps_log
# Usage: vps_log "INFO|ERROR" "Message"
vps_log() {
    local level="$1"
    local msg="$2"
    echo -e "${C_BLUE}[${level}]${C_RESET} ${msg}" >&2
}

# Function: add_vps_finding
# Purpose: Core finding function with extended metadata for this module
# Usage: add_vps_finding "ID" "SEVERITY" "TYPE" "ORIGIN" "CATEGORY" "TITLE" "DESCRIPTION" "EVIDENCE" "REMEDIATION"
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

    # 1. Output to console (Human Readable)
    # Different formatting for Standalone vs Integrated mode logic handled by the caller wrapper?
    # Actually, we can print a standardized pretty format here.
    
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

    # 2. Store for JSON Report (Simple accumulation)
    # Note: Bash JSON construction is tricky, keeping it simple string concatenation for now
    # or relying on a final report generator if needed.
}

#!/bin/bash

# modules/secure-vps/main.sh
# Integrated entrypoint for IronBase

MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load Module Libraries
# Note: we do NOT source common.sh directly because we want to override add_vps_finding.
# However, we might need constants from it.
# Let's source it, then override the function.
source "$MODULE_ROOT/lib/common.sh"
source "$MODULE_ROOT/lib/network.sh"

# Load Scanners
source "$MODULE_ROOT/scanners/internal.sh"
source "$MODULE_ROOT/scanners/external.sh"

module_meta() {
    echo "Name: Secure VPS"
    echo "Description: Comprehensive threat exposure assessment for public VPS."
    echo "Version: 1.0.0"
}

# Globals to track severity counts
VPS_COUNT_CRITICAL=0
VPS_COUNT_HIGH=0
VPS_COUNT_MEDIUM=0
VPS_COUNT_LOW=0

# Override add_vps_finding to bridge to IronBase's add_finding
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

    # Increment counters
    case "$severity" in
        "$SEV_CRITICAL") ((VPS_COUNT_CRITICAL++)) ;;
        "$SEV_HIGH") ((VPS_COUNT_HIGH++)) ;;
        "$SEV_MEDIUM") ((VPS_COUNT_MEDIUM++)) ;;
        "$SEV_LOW") ((VPS_COUNT_LOW++)) ;;
    esac

    # Map to IronBase `add_finding` signature:
    # add_finding "ID" "SEVERITY" "STATUS" "TITLE" "DESCRIPTION" "EVIDENCE" "REMEDIATION"
    
    # We map "severity" directly.
    # We map "status" based on severity (CRITICAL/HIGH/MED -> FAIL, LOW/INFO -> WARN/INFO).
    
    local status="$STATUS_FAIL"
    if [[ "$severity" == "$SEV_INFO" ]]; then
        status="$STATUS_PASS" # Info is usually just info
    elif [[ "$severity" == "$SEV_LOW" ]]; then
        status="$STATUS_WARN"
    fi

    # Format Description to include extra metadata
    local full_desc="[$type] [$origin] $description"

    add_finding "$id" "$severity" "$status" "[$category] $title" "$full_desc" "$evidence" "$remediation"
}

module_scan() {
    # Run the scans
    scan_internal
    scan_external
    
    # Determine exit code based on severity
    if (( VPS_COUNT_CRITICAL > 0 )) || (( VPS_COUNT_HIGH > 0 )); then
        return 1 # Fail the module
    elif (( VPS_COUNT_MEDIUM > 0 )); then
        # Optional: Decide if Medium should fail. Usually Medium implies risk but maybe passing with warnings?
        # User requested: "PASSED WITH FINDINGS" or "FAILED".
        # Core only supports 0 (PASSED) or !0 (FAILED).
        # Let's fail on High/Critical.
        return 0
    fi
    
    return 0
}

module_apply() {
    echo "APPLY: Secure VPS module is Read-Only. No changes applied."
}

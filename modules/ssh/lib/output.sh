#!/bin/bash

# modules/ssh/lib/output.sh
# Handles Output Formatting and Logging for SSH Module

# Output File
LOG_FILE="${VPS_LOG_FILE:-ssh-scan.txt}"

# Counters
COUNT_CRITICAL=0
COUNT_HIGH=0
COUNT_MEDIUM=0
COUNT_LOW=0
COUNT_INFO=0

# Initialize Log File
init_log_file() {
    echo "IronBase - SSH Hardening Scan Report" > "$LOG_FILE"
    echo "====================================" >> "$LOG_FILE"
    echo "Date: $(date)" >> "$LOG_FILE"
    echo "Hostname: $(hostname)" >> "$LOG_FILE"
    echo "Module Version: 2.0.0" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "Findings Details:" >> "$LOG_FILE"
    echo "-----------------" >> "$LOG_FILE"
}

# Function: print_finding
# Prints finding to console and log file
print_finding() {
    local id="$1"
    local severity="$2"
    local type="$3"
    local origin="$4"
    local category="$5"
    local title="$6"
    local description="$7"
    local evidence="$8"
    local recommendation="$9"

    # Update Counters
    case "$severity" in
        "$SEV_CRITICAL") ((COUNT_CRITICAL++)) ;;
        "$SEV_HIGH") ((COUNT_HIGH++)) ;;
        "$SEV_MEDIUM") ((COUNT_MEDIUM++)) ;;
        "$SEV_LOW") ((COUNT_LOW++)) ;;
        "$SEV_INFO") ((COUNT_INFO++)) ;;
    esac

    # --- Console Output ---
    local color="$C_RESET"
    case "$severity" in
        "$SEV_CRITICAL") color="$C_RED" ;;
        "$SEV_HIGH") color="$C_RED" ;;
        "$SEV_MEDIUM") color="$C_YELLOW" ;;
        "$SEV_LOW") color="$C_BLUE" ;;
        "$SEV_INFO") color="$C_RESET" ;;
    esac

    # Console: Short/Readable
    echo -e "${color}[${severity}]${C_RESET} ${C_BOLD}${title}${C_RESET} (${id})"
    echo -e "      Category: $category | Type: $type | Scope: $origin"
    echo -e "      ${C_BOLD}Description:${C_RESET} $description"
    
    # Truncate evidence for console if too long
    local console_evidence="$evidence"
    if [[ ${#evidence} -gt 200 ]]; then
        console_evidence="${evidence:0:200}... (see report for full output)"
    fi
    if [[ -n "$console_evidence" ]]; then
        echo -e "      ${C_BOLD}Evidence:${C_RESET} $console_evidence"
    fi

    if [[ -n "$recommendation" ]]; then
        echo -e "      ${C_BOLD}Rec:${C_RESET} $recommendation"
    fi
    echo ""

    # --- Log File Output ---
    {
        echo "[$severity] $title ($id)"
        echo "Category: $category | Type: $type | Scope: $origin"
        echo "Description: $description"
        if [[ -n "$evidence" ]]; then
            echo "Evidence:"
            echo "$evidence"
        fi
        if [[ -n "$recommendation" ]]; then
            echo "Recommendation: $recommendation"
        fi
        echo "--------------------------------------------------"
    } >> "$LOG_FILE"
}

# Function: print_summary
# Prints summary and determines exit code
print_summary() {
    {
        echo ""
        echo "===================================="
        echo "Scan Summary"
        echo "===================================="
        echo "Critical: $COUNT_CRITICAL"
        echo "High:     $COUNT_HIGH"
        echo "Medium:   $COUNT_MEDIUM"
        echo "Low:      $COUNT_LOW"
        echo "Info:     $COUNT_INFO"
        echo "===================================="
    } >> "$LOG_FILE"

    # Console Summary & Status
    echo "======================================"
    echo -e "${C_BOLD}SSH Scan Summary:${C_RESET}"
    echo -e "${C_RED}Critical: $COUNT_CRITICAL${C_RESET}"
    echo -e "${C_RED}High:     $COUNT_HIGH${C_RESET}"
    echo -e "${C_YELLOW}Medium:   $COUNT_MEDIUM${C_RESET}"
    echo -e "${C_BLUE}Low:      $COUNT_LOW${C_RESET}"
    echo -e "Info:     $COUNT_INFO"
    echo "======================================"

    # Determine Result
    local exit_code=0
    if (( COUNT_CRITICAL > 0 )) || (( COUNT_HIGH > 0 )); then
        echo -e "${C_RED}Result: FAILED (Critical/High findings detected)${C_RESET}"
        exit_code=1
    elif (( COUNT_MEDIUM > 0 )); then
        echo -e "${C_YELLOW}Result: PASSED WITH FINDINGS (Medium findings detected)${C_RESET}"
        exit_code=0
    else
        echo -e "${C_GREEN}Result: PASSED${C_RESET}"
        exit_code=0
    fi

    # Next Steps
    echo ""
    echo -e "${C_BOLD}Next Steps:${C_RESET}"
    echo "1. Review the full report below."
    echo "2. Apply remediations if safe:"
    echo "   ./cmd/ironbase apply --module ssh"
    echo -e "   ${C_YELLOW}WARNING: Review configuration before applying fixes.${C_RESET}"
    echo ""
    echo "Report saved: $(pwd)/$LOG_FILE"
    
    # Add Next Steps to Log
    {
        echo ""
        echo "Next Steps:"
        echo "1. Apply remediations: ./cmd/ironbase apply --module ssh"
        echo "   WARNING: Review configuration before applying fixes."
    } >> "$LOG_FILE"

    return $exit_code
}

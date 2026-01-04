#!/bin/bash

# modules/secure-vps/standalone.sh
# Runnable entrypoint for standalone usage

# Resolve absolute path to module root
MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load Libraries
source "$MODULE_ROOT/lib/common.sh"
source "$MODULE_ROOT/lib/network.sh"

# Load Scanners
source "$MODULE_ROOT/scanners/internal.sh"
source "$MODULE_ROOT/scanners/external.sh"

# Header
echo -e "${C_BOLD}Secure-VPS Standalone Scanner${C_RESET}"
echo "======================================"

# Initialize Log
init_log_file

# Run Scans
scan_internal
scan_external

# Summary
print_summary
exit $?

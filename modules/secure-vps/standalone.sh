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

# Run Scans
scan_internal
scan_external

echo "======================================"
echo -e "${C_GREEN}Scan Complete.${C_RESET}"

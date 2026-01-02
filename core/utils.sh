#!/bin/bash

# core/utils.sh
# Core utility functions for logging and output formatting.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to load a profile config (Mock/Simple grepper for v0)
# Usage: is_module_enabled "module_name" "profile_path"
is_module_enabled() {
    local module_name=$1
    local profile_path=$2
    
    # Check if profile exists
    if [[ ! -f "$profile_path" ]]; then
        return 1
    fi
    
    # Simple logic: check if "module_name" is present and NOT followed by "enabled: false"
    # This is a very basic parser for v0.
    # In a real scenario, use yq or similar.
    # We assume the structure:
    #   module_name:
    #     enabled: true
    
    # Check if module is explicitly disabled
    grep -A 2 "${module_name}:" "$profile_path" | grep "enabled: false" > /dev/null
    if [[ $? -eq 0 ]]; then
        return 1
    fi
    
    # Check if module is explicitly enabled
     grep -A 2 "${module_name}:" "$profile_path" | grep "enabled: true" > /dev/null
    if [[ $? -eq 0 ]]; then
         return 0
    fi
    
    # Default to false if not found?
    return 1
}

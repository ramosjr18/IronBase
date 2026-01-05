#!/bin/bash

# core/engine.sh
# Main orchestration logic for IronBase.

# Load utilities
source "$(dirname "$0")/../core/utils.sh"
source "$(dirname "$0")/../core/findings.sh"

IRONBASE_ROOT="$(dirname "$0")/.."
MODULES_DIR="$IRONBASE_ROOT/modules"
DEFAULT_PROFILE="$IRONBASE_ROOT/profiles/ubuntu-baseline.yaml"

# Load a module file
load_module() {
    local module_name=$1
    local module_path="$MODULES_DIR/$module_name/main.sh"
    
    if [[ -f "$module_path" ]]; then
        source "$module_path"
    else
        log_error "Module not found: $module_name"
        exit 1
    fi
}

# Run a single module
run_module() {
    local action=$1
    local module_name=$2
    local profile=$3
    
    # Load module source
    source "$MODULES_DIR/$module_name/main.sh"

    # Get Metadata
    local mod_name
    mod_name=$(module_meta | grep "Name:" | cut -d: -f2 | xargs)
    
    log_info "Running module: $mod_name ($module_name)"
    
    if [[ "$action" == "scan" ]]; then
        module_scan
        local result=$?
        if [[ $result -eq 0 ]]; then
            log_success "Module $mod_name: PASSED"
        else
            log_warn "Module $mod_name: FAILED/ISSUES FOUND"
        fi
    elif [[ "$action" == "apply" ]]; then
        module_apply
        log_info "Module $mod_name: Apply phase completed."
    fi
}

# Main Engine Function
engine_main() {
    local action=$1
    shift
    
    local target_module=""
    local profile_path="$DEFAULT_PROFILE"
    
    # Parse args (simple for v0)
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --module) target_module="$2"; shift ;;
            --profile) profile_path="$2"; shift ;;
            --force) export IRONBASE_FORCE="true" ;;
            *) ;;
        esac
        shift
    done

    log_info "IronBase Engine v0.1.0 starting..."
    log_info "Action: $action"
    log_info "Profile: $profile_path"

    # Discover modules
    local modules=()
    if [[ -n "$target_module" ]]; then
        modules=("$target_module")
    else
        # List all directories in modules/
        for d in "$MODULES_DIR"/*/; do
            if [[ -d "$d" ]]; then
                modules+=($(basename "$d"))
            fi
        done
    fi

    # Execute
    for mod in "${modules[@]}"; do
        # Check if enabled in profile
        if [[ -n "$target_module" ]]; then
             # Force run if manually specified
             run_module "$action" "$mod" "$profile_path"
        else
             if is_module_enabled "$mod" "$profile_path"; then
                 run_module "$action" "$mod" "$profile_path"
             else
                 # log_info "Skipping module $mod (disabled in profile)"
                 :
             fi
        fi
    done
    
    log_info "Execution completed."
}

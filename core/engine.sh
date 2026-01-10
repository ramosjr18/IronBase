#!/bin/bash

# core/engine.sh
# Main orchestration logic for IronBase.

# Load utilities
source "$(dirname "$0")/../core/utils.sh"
source "$(dirname "$0")/../core/findings.sh"
source "$(dirname "$0")/../core/reporting.sh"

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
    
    # Register module in global report
    register_module "$module_name"
    
    # Set module-specific log paths in run directory
    export VPS_LOG_FILE="$IRONBASE_RUN_DIR/secure-vps.log"
    export VULN_LOG_FILE="$IRONBASE_RUN_DIR/vulnerability.log"
    export VPS_APPLY_LOG="$IRONBASE_RUN_DIR/secure-vps-apply.log"
    # SSH module uses VPS_LOG_FILE (shared from secure-vps pattern)
    # Firewall module uses VPS_APPLY_LOG pattern
    
    log_info "Running module: $mod_name ($module_name)"
    
    # Check if list mode is enabled
    if [[ "$IRONBASE_LIST_MODE" == "true" ]]; then
        if declare -f module_list > /dev/null; then
            module_list
        else
            log_warn "Module $mod_name does not support --list mode"
        fi
    elif [[ "$action" == "scan" ]]; then
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
            --bootstrap) export IRONBASE_BOOTSTRAP="true" ;;
            --list) export IRONBASE_LIST_MODE="true" ;;
            *) ;;
        esac
        shift
    done

    log_info "IronBase Engine v0.1.0 starting..."
    log_info "Action: $action"
    log_info "Profile: $profile_path"
    
    # Initialize reporting system
    local flags_str=""
    [[ "$IRONBASE_FORCE" == "true" ]] && flags_str="${flags_str} --force"
    [[ "$IRONBASE_BOOTSTRAP" == "true" ]] && flags_str="${flags_str} --bootstrap"
    [[ "$IRONBASE_LIST_MODE" == "true" ]] && flags_str="${flags_str} --list"
    
    local run_dir=$(init_reporting "$action" "$profile_path" "$flags_str")
    log_info "Output directory: $run_dir"

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
    
    # Generate final reports (returns exit code)
    log_info "Generating reports..."
    generate_reports
    local exit_code=$?
    
    # Show summary (clean console output)
    if [[ -f "$GLOBAL_RUN_DIR/summary.txt" ]]; then
        echo ""
        cat "$GLOBAL_RUN_DIR/summary.txt"
    fi
    
    log_info "Execution completed."
    log_info "Reports saved to: $GLOBAL_RUN_DIR"
    
    # Cleanup temporary findings file
    if [[ -n "$GLOBAL_FINDINGS_FILE" ]] && [[ -f "$GLOBAL_FINDINGS_FILE" ]]; then
        rm -f "$GLOBAL_FINDINGS_FILE" 2>/dev/null || true
    fi
    
    return $exit_code
}

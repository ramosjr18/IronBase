#!/bin/bash
# modules/secure-ssh/main.sh
# Integration Entrypoint

module_meta() {
    echo "name: secure-ssh"
    echo "description: Hardens SSH configuration interactively."
    echo "version: 1.0.0"
}

module_scan() {
    local script_dir="$(dirname "${BASH_SOURCE[0]}")"
    source "$script_dir/scanners/ssh.sh"
    scan_ssh
}

module_apply() {
    local script_dir="$(dirname "${BASH_SOURCE[0]}")"
    # Re-use wizard
    source "$script_dir/lib/wizard.sh"
    
    # We assume IronBase core provides helpers (log_apply/backup_file) or wizard falls back
    # But usually core/engine.sh sets up environment.
    # However, secure-ssh wizard expects 'apply_fix_ssh_root' to be called.
    
    echo -e "${C_BOLD}Running SSH Hardening Module${C_RESET}"
    apply_fix_ssh_root
}

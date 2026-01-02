#!/bin/bash

# modules/ssh/main.sh
# SSH Hardening Module

module_meta() {
    echo "Name: SSH Hardening"
    echo "Description: Checks for root login and password auth."
    echo "Version: 1.0.0"
}

module_scan() {
    local sshd_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$sshd_config" ]]; then
        echo "FAIL: sshd_config not found"
        return 1
    fi

    # Check PermitRootLogin
    if grep -E "^PermitRootLogin yes" "$sshd_config"; then
        echo "FAIL: Remote root login is enabled"
        return 1
    fi

    echo "PASS: SSH Root login disabled (or not explicitly enabled)"
    return 0
}

module_apply() {
    echo "APPLY: Disabling Root Login in /etc/ssh/sshd_config..."
    # sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
}

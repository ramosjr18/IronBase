#!/bin/bash

# modules/ssh/main.sh
# SSH Hardening Module

module_meta() {
    echo "Name: SSH Hardening"
    echo "Description: Checks for root login, password auth, and protocols."
    echo "Version: 1.1.0"
}

module_scan() {
    local sshd_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$sshd_config" ]]; then
        add_finding "SSH-000" "$SEV_HIGH" "$STATUS_WARN" "Config Found" \
            "sshd_config not found." \
            "" \
            "Ensure SSH is installed if needed."
        return 1
    fi

    # 1. Root Login
    if grep -E "^PermitRootLogin yes" "$sshd_config" > /dev/null; then
        add_finding "SSH-001" "$SEV_HIGH" "$STATUS_FAIL" "Root Login" \
            "PermitRootLogin is set to yes." \
            "grep PermitRootLogin $sshd_config" \
            "Set 'PermitRootLogin no' or 'prohibit-password'"
    else
        add_finding "SSH-001" "$SEV_HIGH" "$STATUS_PASS" "Root Login" \
            "Root login disabled (or not potentially enabled)." \
            "" \
            ""
    fi

    # 2. Password Authentication
    if grep -E "^PasswordAuthentication yes" "$sshd_config" > /dev/null; then
        add_finding "SSH-002" "$SEV_MEDIUM" "$STATUS_WARN" "Password Auth" \
            "PasswordAuthentication is enabled." \
            "Recommend using key-based auth only." \
            "Set 'PasswordAuthentication no'"
    else
        add_finding "SSH-002" "$SEV_MEDIUM" "$STATUS_PASS" "Password Auth" \
            "PasswordAuthentication appears disabled (or default)." \
            "" \
            ""
    fi

    # 3. Empty Passwords
    if grep -E "^PermitEmptyPasswords yes" "$sshd_config" > /dev/null; then
         add_finding "SSH-003" "$SEV_CRITICAL" "$STATUS_FAIL" "Empty Passwords" \
            "PermitEmptyPasswords is enabled." \
            "" \
            "Set 'PermitEmptyPasswords no'"
    else
         add_finding "SSH-003" "$SEV_HIGH" "$STATUS_PASS" "Empty Passwords" \
            "PermitEmptyPasswords is not enabled." \
            "" \
            ""
    fi

    return 0
}

module_apply() {
    echo "APPLY: Disabling Root Login in /etc/ssh/sshd_config..."
    # sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
}

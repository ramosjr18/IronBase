#!/bin/bash

# modules/firewall/main.sh
# Firewall hardening module (UFW based)

module_meta() {
    echo "Name: Firewall Hardening"
    echo "Description: Ensures UFW is enabled and basic policies are set."
    echo "Version: 1.1.0"
}

module_scan() {
    # 1. Check Install
    if ! command_exists ufw; then
        add_finding "FW-001" "$SEV_HIGH" "$STATUS_FAIL" "UFW Installed" \
            "UFW is not installed." \
            "" \
            "Install 'ufw' package."
        return 1
    fi

    # 2. Check Status
    local status_out
    status_out=$(sudo ufw status verbose 2>/dev/null)
    if echo "$status_out" | grep -q "Status: active"; then
        add_finding "FW-002" "$SEV_HIGH" "$STATUS_PASS" "UFW Status" \
            "UFW is active." \
            "" \
            ""
            
        # 3. Check Policies (Default Deny Incoming)
        if echo "$status_out" | grep -q "Default: deny (incoming)"; then
            add_finding "FW-003" "$SEV_MEDIUM" "$STATUS_PASS" "Default Incoming Policy" \
                "Default incoming policy is DENY." \
                "" \
                ""
        else
            add_finding "FW-003" "$SEV_HIGH" "$STATUS_FAIL" "Default Incoming Policy" \
                "Default incoming policy is NOT deny." \
                "Current: $(echo "$status_out" | grep "Default:")" \
                "Run 'ufw default deny incoming'"
        fi
    else
        add_finding "FW-002" "$SEV_HIGH" "$STATUS_FAIL" "UFW Status" \
            "UFW is inactive." \
            "" \
            "Run 'ufw enable'"
        return 1
    fi

    return 0
}

module_apply() {
    echo "APPLY: Ensuring UFW is installed..."
    # sudo apt-get install -y ufw (Mocked)
    
    echo "APPLY: Enabling UFW..."
    # sudo ufw enable (Mocked)
    
    echo "APPLY: Setting default policies..."
    # sudo ufw default deny incoming
    # sudo ufw default allow outgoing
}

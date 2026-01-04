#!/bin/bash

# modules/secure-vps/scanners/internal.sh
# Internal (Host-based) Security Checks

scan_internal() {
    vps_log "INFO" "Starting Internal Scan (Host-based)..."

    # --- 1. Kernel & System Surface ---
    
    # Kernel Version
    local kernel_version=$(uname -r)
    add_vps_finding "INT-SYS-001" "$SEV_INFO" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "System" \
        "Kernel Version" \
        "Running Kernel: $kernel_version" \
        "uname -r" \
        "Ensure kernel is up to date."

    # ASLR Check
    if command -v sysctl &> /dev/null; then
        local aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
        if [[ -n "$aslr" && "$aslr" != "2" ]]; then
            add_vps_finding "INT-SYS-002" "$SEV_HIGH" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "System" \
                "ASLR Disabled or Weak" \
                "kernel.randomize_va_space is $aslr (Expected: 2)" \
                "sysctl kernel.randomize_va_space" \
                "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf"
        fi
    fi

    # Users with UID 0 (Root equivalents)
    local root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
    if [[ $(echo "$root_users" | wc -l) -gt 1 ]]; then
         add_vps_finding "INT-USR-001" "$SEV_CRITICAL" "$TYPE_VULN" "$ORIGIN_INTERNAL" "Users" \
            "Multiple UID 0 users found" \
            "Users: $(echo $root_users | tr '\n' ' ')" \
            "/etc/passwd" \
            "Remove unnecessary root-equivalent accounts."
    fi

    # Empty Password Fields
    if [[ -f "/etc/shadow" ]] && grep -q "^[^:]*::" /etc/shadow 2>/dev/null; then
         add_vps_finding "INT-USR-002" "$SEV_CRITICAL" "$TYPE_VULN" "$ORIGIN_INTERNAL" "Users" \
            "Accounts with empty passwords found" \
            "Check /etc/shadow for empty password fields" \
            "grep '^[^:]*::' /etc/shadow" \
            "Lock or set passwords for affected accounts."
    fi

    # --- 2. Services & Daemons ---
    # Check for active services listening on non-localhost
    
    # Helper to find potentially dangerous services on public interfaces
    # Simplification: we use ss to find listening ports not on 127.0.0.1
    if command -v ss &> /dev/null; then
        local exposed_Listeners=$(ss -lntu | awk '$4 !~ /^127\.0\.0\.1/ && $4 !~ /^\[::1\]/ && NR>1 {print $0}')
        
        if [[ -n "$exposed_Listeners" ]]; then
             add_vps_finding "INT-NET-001" "$SEV_MEDIUM" "$TYPE_RISK" "$ORIGIN_INTERNAL" "Network" \
                "Services listening on non-loopback interfaces" \
                "Potentially exposed services found." \
                "$exposed_Listeners" \
                "Review if these services need to be exposed to 0.0.0.0 or public IP."
        fi
    fi

    # --- 3. SSH Configuration ---
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        # Root Login
        if grep -E "^PermitRootLogin yes" "$sshd_config" > /dev/null; then
             add_vps_finding "INT-SSH-001" "$SEV_HIGH" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "Auth" \
                "SSH Root Login Enabled" \
                "PermitRootLogin is set to yes" \
                "" \
                "Set PermitRootLogin no"
        fi
        
        # Password Auth
        if grep -E "^PasswordAuthentication yes" "$sshd_config" > /dev/null; then
             add_vps_finding "INT-SSH-002" "$SEV_MEDIUM" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "Auth" \
                "SSH Password Auth Enabled" \
                "PasswordAuthentication is set to yes" \
                "" \
                "Disable PasswordAuthentication, use keys only."
        fi
    fi

    # --- 4. System Anomalies ---
    # World Writable Dirs in PATH (Generic check)
    if echo $PATH | tr ':' '\n' | xargs -I {} find {} -maxdepth 0 -perm -002 2>/dev/null; then
         add_vps_finding "INT-SYS-003" "$SEV_HIGH" "$TYPE_VULN" "$ORIGIN_INTERNAL" "System" \
            "World Writable Directory in PATH" \
            "Directories in PATH are writable by others." \
            "" \
            "Fix permissions on system directories."
    fi
}

#!/bin/bash

# modules/secure-vps/scanners/internal.sh
# Internal (Host-based) Security Checks

scan_internal() {
    vps_log "INFO" "Starting Internal Scan (Host-based)..."

    # --- 1. Kernel & System Surface ---
    
    # Kernel Version
    local kernel_version=$(uname -r)
    # Parse Major and Minor version
    local k_major=""
    local k_minor=""
    if [[ "$kernel_version" =~ ^([0-9]+)\.([0-9]+) ]]; then
        k_major="${BASH_REMATCH[1]}"
        k_minor="${BASH_REMATCH[2]}"
    fi

    # Logic:
    # < 4.19 : FAIL (EOL)
    # 4.19 - 5.15 : WARN (Old/LTS)
    # >= 5.15 : PASS
    
    if [[ -n "$k_major" ]]; then
        if (( k_major < 4 )) || { (( k_major == 4 )) && (( k_minor < 19 )); }; then
            add_vps_finding "INT-SYS-001" "$SEV_HIGH" "$TYPE_VULN" "$ORIGIN_INTERNAL" "System" \
                "Kernel EOL Detected" \
                "Running Kernel: $kernel_version (Older than 4.19)" \
                "uname -r" \
                "Upgrade to a supported LTS kernel immediately (5.15+ recommended)."
        elif (( k_major == 4 )) || { (( k_major == 5 )) && (( k_minor < 15 )); }; then
             add_vps_finding "INT-SYS-001" "$SEV_LOW" "$TYPE_RISK" "$ORIGIN_INTERNAL" "System" \
                "Legacy Kernel Detected" \
                "Running Kernel: $kernel_version (Supported but older generation)" \
                "uname -r" \
                "Plan upgrade to modern LTS kernel (5.15+)."
        else
             add_vps_finding "INT-SYS-001" "$SEV_INFO" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "System" \
                "Kernel Version OK" \
                "Running Kernel: $kernel_version (Modern)" \
                "uname -r" \
                "Keep kernel updated."
        fi
    else
        # Fallback if parsing fails
        add_vps_finding "INT-SYS-001" "$SEV_INFO" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "System" \
            "Kernel Version (Unparsed)" \
            "Running Kernel: $kernel_version" \
            "uname -r" \
            "Ensure kernel is up to date."
    fi

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
    
    if command -v ss &> /dev/null; then
        # Capture raw lines of exposed services (excluding 127.0.0.1 and ::1)
        # Note: Local Address:Port is usually column 5 in 'ss -lntu'
        local raw_exposed=$(ss -lntu | awk '$5 !~ /^127\.0\.0\.1/ && $5 !~ /^\[::1\]/ && NR>1 {print $0}')
        
        if [[ -n "$raw_exposed" ]]; then
            local list_critical=""
            local list_expected=""
            local list_unknown=""
            
            # Classification Lists
            # Internal/Critical: DBs, Docker, Mgmt
            local ports_critical="^(6379|543[0-9]|3306|27017|9200|237[0-9])$" 
            # Expected Public: Web (80, 443), VoIP/RTC (3478, 7880, 7881)
            local ports_expected="^(80|443|3478|7880|7881)$"

            while read -r line; do
                # Extract port. Format is usually "IP:PORT" or "*:PORT"
                # $5 in ss output is Local_Address:Port. 
                # awk logic to split by last colon
                local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
                
                if [[ "$port" =~ $ports_critical ]]; then
                    list_critical+="${line}\n"
                elif [[ "$port" =~ $ports_expected ]]; then
                    list_expected+="${line}\n"
                else
                    list_unknown+="${line}\n"
                fi
            done <<< "$raw_exposed"

            # 2a. Critical/Internal Services Exposed
            if [[ -n "$list_critical" ]]; then
                 add_vps_finding "INT-NET-002" "$SEV_CRITICAL" "$TYPE_RISK" "$ORIGIN_INTERNAL" "Network" \
                    "Critical Internal Services Exposed" \
                    "Services usually meant for internal use (DB, Docker) are listening externally." \
                    "$(echo -e $list_critical)" \
                    "IMMEDIATE ACTION: Bind these services to 127.0.0.1 or use a Firewall/VPN."
            fi

            # 2b. Expected/Public Services
            if [[ -n "$list_expected" ]]; then
                 add_vps_finding "INT-NET-003" "$SEV_INFO" "$TYPE_RISK" "$ORIGIN_INTERNAL" "Network" \
                    "Known Public Services Detected" \
                    "Standard public services (Web, VoIP) are active." \
                    "$(echo -e $list_expected)" \
                    "Verify versions and configuration (WAF/Cloudflare etc)."
            fi

            # 2c. Unknown/Other Services
            if [[ -n "$list_unknown" ]]; then
                 add_vps_finding "INT-NET-001" "$SEV_MEDIUM" "$TYPE_RISK" "$ORIGIN_INTERNAL" "Network" \
                    "Unclassified Services Exposed" \
                    "Services listening on public interfaces not in allow-list." \
                    "$(echo -e $list_unknown)" \
                    "Review each service. If internal only, bind to localhost."
            fi
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

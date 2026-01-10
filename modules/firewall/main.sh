#!/bin/bash

# modules/firewall/main.sh
# Firewall hardening module (UFW based)

module_meta() {
    echo "Name: Firewall Hardening"
    echo "Description: Ensures UFW is enabled and basic policies are set. Advanced scan checks for rule completeness, interference, and service exposure."
    echo "Version: 2.0.0"
}

module_scan() {
    # ========================================================================
    # BASELINE CHECKS (Fail-Fast Behavior)
    # ========================================================================
    # This module implements fail-fast behavior: if UFW is not installed or
    # inactive, the scan stops immediately. Advanced checks (FW-004 through
    # FW-011) are only meaningful when UFW is active and operational.
    # 
    # Rationale: Running advanced firewall checks against an inactive firewall
    # would produce misleading or irrelevant results. This demonstrates
    # intentional design maturity and prevents false positives.
    # ========================================================================
    
    # 1. Check Install
    # FAIL-FAST: If UFW is not installed, stop scan immediately.
    # No further checks can be performed without UFW.
    if ! command_exists ufw; then
        add_finding "FW-001" "$SEV_HIGH" "$STATUS_FAIL" "UFW Installed" \
            "UFW is not installed. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness." \
            "" \
            "Install 'ufw' package."
        return 1
    fi

    # 2. Check Status
    # FAIL-FAST: If UFW is inactive, stop scan immediately.
    # Advanced checks (FW-004 through FW-011) require UFW to be active.
    # If UFW is inactive, the firewall scan stops after FW-002.
    local status_out
    status_out=$(sudo ufw status verbose 2>/dev/null)
    if echo "$status_out" | grep -q "Status: active"; then
        add_finding "FW-002" "$SEV_HIGH" "$STATUS_PASS" "UFW Status" \
            "UFW is active. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness." \
            "" \
            ""
            
        # 3. Check Policies (Default Deny Incoming)
        # Only executes if UFW is active (FW-002 passed)
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
            "UFW is inactive. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness." \
            "" \
            "Run 'ufw enable'"
        # FAIL-FAST: Stop scan here. Advanced checks (FW-004 through FW-011) are skipped.
        return 1
    fi

    # ========================================================================
    # ADVANCED CHECKS (FW-004 through FW-011)
    # ========================================================================
    # These checks only execute if UFW is installed AND active (FW-002 passed).
    # They perform deeper analysis of firewall rules, interference, and
    # service exposure correlation.
    # ========================================================================

    # 4. Specific Allow Rules Exist
    local numbered_out
    numbered_out=$(sudo ufw status numbered 2>/dev/null)
    if [[ -n "$numbered_out" ]]; then
        local allow_count=$(echo "$numbered_out" | grep -c "ALLOW IN" || echo "0")
        
        # Check for SSH port dynamically
        local ssh_port="22"
        if command_exists ss; then
            local ssh_listening=$(ss -lnt 2>/dev/null | grep ":22 " | head -1)
            if [[ -n "$ssh_listening" ]]; then
                # Check if SSH port is explicitly allowed
                local ssh_allowed=$(echo "$numbered_out" | grep -E "ALLOW IN.*22" || echo "")
                if [[ -n "$ssh_allowed" ]]; then
                    # SSH is allowed, check if at least one allow rule exists
                    if [[ "$allow_count" -eq 0 ]]; then
                        add_finding "FW-004" "$SEV_HIGH" "$STATUS_FAIL" "Specific Allow Rules Exist" \
                            "Default deny exists with no explicit ALLOW IN rules detected. System may be completely locked down or SSH access may be blocked." \
                            "ufw status numbered: No ALLOW IN rules found" \
                            "Review firewall rules: 'sudo ufw status numbered'. Ensure required services (SSH, web) have explicit allow rules."
                    else
                        add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                            "At least one explicit ALLOW IN rule exists ($allow_count total). SSH port appears to be allowed." \
                            "Found $allow_count ALLOW IN rules in 'ufw status numbered'" \
                            ""
                    fi
                else
                    # SSH is listening but not explicitly allowed - could be allowed by default policy
                    if [[ "$allow_count" -eq 0 ]]; then
                        add_finding "FW-004" "$SEV_HIGH" "$STATUS_WARN" "Specific Allow Rules Exist" \
                            "SSH port 22 is listening but no explicit ALLOW IN rule found. May be blocked if default deny is active." \
                            "SSH listening: $ssh_listening | ufw status: No explicit allow for port 22" \
                            "Verify SSH access works. Consider: 'sudo ufw allow 22/tcp' or review default policy."
                    else
                        add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                            "Explicit ALLOW IN rules exist ($allow_count total). SSH port 22 may be covered by default policy or other rules." \
                            "Found $allow_count ALLOW IN rules" \
                            ""
                    fi
                fi
            else
                # No SSH listening, just check for any allow rules
                if [[ "$allow_count" -eq 0 ]]; then
                    add_finding "FW-004" "$SEV_HIGH" "$STATUS_FAIL" "Specific Allow Rules Exist" \
                        "Default deny exists with no explicit ALLOW IN rules. System may be completely locked down." \
                        "ufw status numbered: No ALLOW IN rules found" \
                        "Review firewall rules: 'sudo ufw status numbered'. Add explicit allow rules for required services."
                else
                    add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                        "At least one explicit ALLOW IN rule exists ($allow_count total)." \
                        "Found $allow_count ALLOW IN rules" \
                        ""
                fi
            fi
        else
            # ss not available, just check allow count
            if [[ "$allow_count" -eq 0 ]]; then
                add_finding "FW-004" "$SEV_HIGH" "$STATUS_FAIL" "Specific Allow Rules Exist" \
                    "Default deny exists with no explicit ALLOW IN rules detected." \
                    "ufw status numbered: No ALLOW IN rules found" \
                    "Review firewall rules: 'sudo ufw status numbered'. Ensure required services have explicit allow rules."
            else
                add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                    "At least one explicit ALLOW IN rule exists ($allow_count total)." \
                    "Found $allow_count ALLOW IN rules" \
                    ""
            fi
        fi
    fi

    # 5. Docker / nftables Interference
    local docker_active=0
    local docker_chains=0
    
    if command_exists systemctl && systemctl is-active --quiet docker 2>/dev/null; then
        docker_active=1
    elif command_exists docker && docker info &>/dev/null; then
        docker_active=1
    fi
    
    if [[ $docker_active -eq 1 ]]; then
        # Check for Docker chains in iptables
        if command_exists iptables; then
            local ipt_docker=$(sudo iptables -L -n 2>/dev/null | grep -i "DOCKER" | head -1)
            if [[ -n "$ipt_docker" ]]; then
                docker_chains=1
            fi
        fi
        
        # Check for Docker in nftables
        if command_exists nft && sudo nft list ruleset 2>/dev/null | grep -qi "docker"; then
            docker_chains=1
        fi
        
        if [[ $docker_chains -eq 1 ]]; then
            add_finding "FW-005" "$SEV_MEDIUM" "$STATUS_WARN" "Docker / nftables Interference" \
                "Docker service is active and appears to manipulate firewall rules (DOCKER chains detected). Docker may bypass or interfere with UFW rules." \
                "Docker active: yes | DOCKER chains found in iptables/nftables" \
                "Review Docker networking mode and UFW integration. Consider: Docker may bypass UFW - verify port exposure independently with 'ss -lnt'."
        else
            add_finding "FW-005" "$SEV_LOW" "$STATUS_PASS" "Docker / nftables Interference" \
                "Docker service is active but no DOCKER firewall chains detected. Potential interference may exist but not confirmed." \
                "Docker active: yes | No DOCKER chains detected" \
                ""
        fi
    else
        add_finding "FW-005" "$SEV_LOW" "$STATUS_PASS" "Docker / nftables Interference" \
            "Docker service is not active or not detected." \
            "" \
            ""
    fi

    # 6. Multiple Firewalls Active
    local firewall_count=0
    local active_firewalls=""
    
    # Check UFW
    if command_exists ufw && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        ((firewall_count++))
        active_firewalls="${active_firewalls}ufw "
    fi
    
    # Check firewalld
    if command_exists firewall-cmd && sudo firewall-cmd --state 2>/dev/null | grep -q "running"; then
        ((firewall_count++))
        active_firewalls="${active_firewalls}firewalld "
    fi
    
    # Check nftables
    if command_exists nft && sudo nft list ruleset 2>/dev/null | grep -q "table"; then
        local nft_table_count=$(sudo nft list tables 2>/dev/null | wc -l)
        if [[ $nft_table_count -gt 0 ]]; then
            ((firewall_count++))
            active_firewalls="${active_firewalls}nftables "
        fi
    fi
    
    # Check raw iptables (not managed by UFW)
    if command_exists iptables; then
        local ipt_rules=$(sudo iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | grep -v "ACCEPT.*all.*--.*lo\|DROP.*all.*--.*0.0.0.0/0" | head -5)
        if [[ -n "$ipt_rules" ]]; then
            # Check if rules are from UFW or manual
            if ! sudo iptables -L -n 2>/dev/null | grep -q "Chain ufw"; then
                # Non-UFW iptables rules exist
                ((firewall_count++))
                active_firewalls="${active_firewalls}iptables(manual) "
            fi
        fi
    fi
    
    if [[ $firewall_count -gt 1 ]]; then
        add_finding "FW-006" "$SEV_HIGH" "$STATUS_FAIL" "Multiple Firewalls Active" \
            "Multiple firewall systems are active simultaneously. This can cause conflicts, unexpected behavior, and rule enforcement issues." \
            "Active firewalls: ${active_firewalls}" \
            "Disable redundant firewall systems. Keep only one: UFW (recommended for Ubuntu) or firewalld. Remove others: 'sudo systemctl disable firewalld' or 'sudo systemctl stop nftables'."
    else
        add_finding "FW-006" "$SEV_MEDIUM" "$STATUS_PASS" "Multiple Firewalls Active" \
            "Only one firewall system is active (${active_firewalls:-none detected})." \
            "Active: ${active_firewalls:-none}" \
            ""
    fi

    # 7. Real Service Exposure (Correlated)
    if command_exists ss; then
        local listening_services=$(ss -lntup 2>/dev/null | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0/ || $5 ~ /^\[::\]/ || $5 ~ /^\*/) {print $1, $5, $7}' | head -10)
        
        if [[ -n "$listening_services" ]]; then
            local exposed_ports=""
            local unmanaged_ports=""
            
            while IFS= read -r service_line; do
                if [[ -z "$service_line" ]]; then continue; fi
                
                local port=$(echo "$service_line" | awk '{print $2}' | awk -F: '{print $NF}' | sed 's/]//')
                local proto=$(echo "$service_line" | awk '{print $1}')
                
                # Check if port has explicit UFW rule
                local ufw_rule=$(echo "$numbered_out" | grep -E "($port|$proto)" | grep -E "(ALLOW|DENY)" | head -1)
                
                if [[ -z "$ufw_rule" ]]; then
                    unmanaged_ports="${unmanaged_ports}${proto} ${port}; "
                else
                    exposed_ports="${exposed_ports}${proto} ${port}; "
                fi
            done <<< "$listening_services"
            
            if [[ -n "$unmanaged_ports" ]]; then
                add_finding "FW-007" "$SEV_HIGH" "$STATUS_FAIL" "Real Service Exposure (Correlated)" \
                    "Services are listening on public interfaces (0.0.0.0 or ::) without explicit firewall control. These ports may be exposed to the internet without UFW rules." \
                    "Unmanaged services: ${unmanaged_ports} | Check: 'ss -lntup | grep -E \"0.0.0.0|::\"'" \
                    "Review listening services: 'ss -lntup'. Add explicit UFW rules for required services: 'sudo ufw allow <port>/<proto>'. Block unnecessary services: 'sudo ufw deny <port>/<proto>' or bind to 127.0.0.1."
            else
                add_finding "FW-007" "$SEV_MEDIUM" "$STATUS_PASS" "Real Service Exposure (Correlated)" \
                    "All detected public listeners appear to have corresponding UFW rules or are managed by default policy." \
                    "Public listeners found with firewall rules" \
                    ""
            fi
        else
            add_finding "FW-007" "$SEV_LOW" "$STATUS_PASS" "Real Service Exposure (Correlated)" \
                "No services detected listening on public interfaces (0.0.0.0 or ::)." \
                "" \
                ""
        fi
    else
        add_finding "FW-007" "$SEV_INFO" "$STATUS_WARN" "Real Service Exposure (Correlated)" \
            "Cannot perform service exposure correlation check: 'ss' command not available." \
            "" \
            "Install 'iproute2' package to enable service exposure analysis."
    fi

    # 8. Forwarding / NAT Policy
    local ipv4_forward=0
    local ipv6_forward=0
    
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    fi
    
    if [[ -f /proc/sys/net/ipv6/conf/all/forwarding ]]; then
        ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
    fi
    
    local forwarding_enabled=0
    if [[ "$ipv4_forward" == "1" ]] || [[ "$ipv6_forward" == "1" ]]; then
        forwarding_enabled=1
    fi
    
    if [[ $forwarding_enabled -eq 1 ]]; then
        # Check if UFW has forwarding/routing rules
        local ufw_forward=$(echo "$status_out" | grep -i "routed" || echo "")
        local ufw_forward_rules=$(echo "$numbered_out" | grep -i "route" || echo "")
        
        if [[ -z "$ufw_forward" && -z "$ufw_forward_rules" ]]; then
            add_finding "FW-008" "$SEV_HIGH" "$STATUS_FAIL" "Forwarding / NAT Policy" \
                "IP forwarding is enabled (IPv4: $ipv4_forward, IPv6: $ipv6_forward) but no explicit UFW routing/forwarding rules detected. System may be acting as router without firewall control." \
                "sysctl: net.ipv4.ip_forward=$ipv4_forward, net.ipv6.conf.all.forwarding=$ipv6_forward | UFW routed: none" \
                "Review IP forwarding requirement. If router/NAT is intentional, configure UFW forwarding rules: 'sudo ufw route allow in on <interface> out on <interface>'. If not needed, disable: 'sudo sysctl -w net.ipv4.ip_forward=0'."
        else
            add_finding "FW-008" "$SEV_MEDIUM" "$STATUS_PASS" "Forwarding / NAT Policy" \
                "IP forwarding is enabled but UFW routing/forwarding rules are present or configured." \
                "Forwarding enabled | UFW routing rules detected" \
                ""
        fi
    else
        add_finding "FW-008" "$SEV_LOW" "$STATUS_PASS" "Forwarding / NAT Policy" \
            "IP forwarding is disabled. System is not acting as router." \
            "net.ipv4.ip_forward=$ipv4_forward, net.ipv6.conf.all.forwarding=$ipv6_forward" \
            ""
    fi

    # 9. Logging & Rate Limiting
    local ufw_logging=$(echo "$status_out" | grep -i "Logging:" | awk '{print $2}' || echo "off")
    local limit_rules=$(echo "$numbered_out" | grep -c "limit" || echo "0")
    
    if [[ "$ufw_logging" == "off" ]] && [[ "$limit_rules" -eq 0 ]]; then
        add_finding "FW-009" "$SEV_MEDIUM" "$STATUS_WARN" "Logging & Rate Limiting" \
            "UFW logging is disabled and no rate-limiting rules detected. No protection against brute-force attacks or audit trail for firewall events." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            "Enable UFW logging for security auditing: 'sudo ufw logging on'. Consider rate-limiting rules for SSH: 'sudo ufw limit 22/tcp'."
    elif [[ "$ufw_logging" == "off" ]]; then
        add_finding "FW-009" "$SEV_LOW" "$STATUS_WARN" "Logging & Rate Limiting" \
            "UFW logging is disabled but rate-limiting rules exist ($limit_rules found). Limited protection without audit trail." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            "Enable UFW logging for security auditing: 'sudo ufw logging on'."
    elif [[ "$limit_rules" -eq 0 ]]; then
        add_finding "FW-009" "$SEV_LOW" "$STATUS_WARN" "Logging & Rate Limiting" \
            "UFW logging is enabled but no rate-limiting rules detected. Logging provides audit trail but no automatic brute-force protection." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            "Consider adding rate-limiting rules for SSH and other exposed services: 'sudo ufw limit 22/tcp'."
    else
        add_finding "FW-009" "$SEV_MEDIUM" "$STATUS_PASS" "Logging & Rate Limiting" \
            "UFW logging is enabled ($ufw_logging) and rate-limiting rules exist ($limit_rules found)." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            ""
    fi

    # 10. IPv6 Enforcement
    local ufw_ipv6_enabled="no"
    if [[ -f /etc/default/ufw ]]; then
        ufw_ipv6_enabled=$(grep "^IPV6=" /etc/default/ufw 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "no")
    fi
    
    local ipv6_rules=0
    if [[ "$ufw_ipv6_enabled" == "yes" ]]; then
        ipv6_rules=$(echo "$numbered_out" | grep -c "v6" || echo "0")
        # Also check for IPv6 specific output
        local ufw_ipv6_status=$(sudo ufw status verbose 2>/dev/null | grep -i "ipv6" || echo "")
        
        if [[ -n "$ufw_ipv6_status" ]]; then
            add_finding "FW-010" "$SEV_MEDIUM" "$STATUS_PASS" "IPv6 Enforcement" \
                "IPv6 is enabled in UFW configuration (IPV6=yes) and IPv6 rules appear to be present." \
                "/etc/default/ufw: IPV6=$ufw_ipv6_enabled | IPv6 rules: detected" \
                ""
        else
            add_finding "FW-010" "$SEV_HIGH" "$STATUS_WARN" "IPv6 Enforcement" \
                "IPv6 is enabled in UFW configuration (IPV6=yes) but IPv6 rules may not be active or enforced. IPv6 traffic may bypass firewall." \
                "/etc/default/ufw: IPV6=$ufw_ipv6_enabled | IPv6 rules: not clearly detected" \
                "Verify IPv6 rules are active: 'sudo ufw status verbose'. If IPv6 is not needed, disable: Set IPV6=no in /etc/default/ufw and restart UFW."
        fi
    else
        # Check if IPv6 is actually disabled on system
        local ipv6_system_disabled=0
        if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
            local ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
            if [[ "$ipv6_disabled" == "1" ]]; then
                ipv6_system_disabled=1
            fi
        fi
        
        if [[ $ipv6_system_disabled -eq 0 ]]; then
            # IPv6 is enabled system-wide but UFW IPv6 is disabled
            add_finding "FW-010" "$SEV_HIGH" "$STATUS_FAIL" "IPv6 Enforcement" \
                "IPv6 is disabled in UFW (IPV6=no) but IPv6 is enabled system-wide. IPv6 traffic may bypass UFW firewall completely." \
                "/etc/default/ufw: IPV6=$ufw_ipv6_enabled | System IPv6: enabled" \
                "Enable IPv6 in UFW: Set IPV6=yes in /etc/default/ufw, then 'sudo ufw reload'. Or disable IPv6 system-wide if not needed: 'sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1'."
        else
            add_finding "FW-010" "$SEV_MEDIUM" "$STATUS_PASS" "IPv6 Enforcement" \
                "IPv6 is disabled in UFW and system-wide. No IPv6 firewall enforcement needed." \
                "UFW IPV6=$ufw_ipv6_enabled | System IPv6: disabled" \
                ""
        fi
    fi

    # 11. Configuration Drift
    if command_exists ss; then
        local listening_ports=$(ss -lnt 2>/dev/null | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0/ || $5 ~ /^\[::\]/) {print $5}' | awk -F: '{print $NF}' | sed 's/]//' | sort -u)
        local ufw_allowed_ports=$(echo "$numbered_out" | grep "ALLOW" | grep -oE "[0-9]+(/tcp|/udp)?" | grep -oE "[0-9]+" | sort -u)
        
        if [[ -n "$listening_ports" ]]; then
            local unaccounted_ports=""
            local accounted_count=0
            
            for port in $listening_ports; do
                if [[ -z "$port" ]]; then continue; fi
                
                local found=0
                for ufw_port in $ufw_allowed_ports; do
                    if [[ "$port" == "$ufw_port" ]]; then
                        found=1
                        ((accounted_count++))
                        break
                    fi
                done
                
                if [[ $found -eq 0 ]]; then
                    unaccounted_ports="${unaccounted_ports}${port} "
                fi
            done
            
            if [[ -n "$unaccounted_ports" ]]; then
                add_finding "FW-011" "$SEV_MEDIUM" "$STATUS_WARN" "Configuration Drift" \
                    "Services are listening on ports that do not have corresponding UFW allow rules. Configuration drift detected - firewall rules may not match actual service exposure." \
                    "Unaccounted ports: ${unaccounted_ports} | Listening: $(echo $listening_ports | tr '\n' ' ') | UFW allowed: $(echo $ufw_allowed_ports | tr '\n' ' ')" \
                    "Review port exposure: 'ss -lnt | grep -E \"0.0.0.0|::\"'. Align firewall rules: Add UFW allow rules for required services or stop/bind unnecessary services to localhost."
            else
                add_finding "FW-011" "$SEV_LOW" "$STATUS_PASS" "Configuration Drift" \
                    "All listening ports on public interfaces appear to have corresponding UFW rules or are managed by default policy." \
                    "Ports aligned: $(echo $listening_ports | tr '\n' ' ')" \
                    ""
            fi
        else
            add_finding "FW-011" "$SEV_LOW" "$STATUS_PASS" "Configuration Drift" \
                "No services detected listening on public interfaces. No configuration drift detected." \
                "" \
                ""
        fi
    else
        add_finding "FW-011" "$SEV_INFO" "$STATUS_WARN" "Configuration Drift" \
            "Cannot perform configuration drift check: 'ss' command not available." \
            "" \
            "Install 'iproute2' package to enable configuration drift analysis."
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

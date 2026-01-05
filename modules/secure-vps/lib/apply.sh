#!/bin/bash

# modules/secure-vps/lib/apply.sh
# Handles interactive remediation

APPLY_LOG="${VPS_APPLY_LOG:-secure-vps-apply.log}"

# --- Utility Functions ---

init_apply_log() {
    echo "IronBase - Secure VPS Remediation Log" > "$APPLY_LOG"
    echo "Date: $(date)" >> "$APPLY_LOG"
    echo "Hostname: $(hostname)" >> "$APPLY_LOG"
    echo "-------------------------------------" >> "$APPLY_LOG"
}

log_apply() {
    local status="$1" # [INFO], [SUCCESS], [SKIP], [ERROR]
    local msg="$2"
    echo "[$status] $msg" >> "$APPLY_LOG"
}

# Prompt user with Yes/No/Skip
# Returns 0 for Yes, 1 for No/Skip
confirm_action() {
    local prompt="$1"
    local default="${2:-N}" # Default to N for safety

    local options="[y/N]"
    if [[ "$default" == "Y" ]]; then options="[Y/n]"; fi

    read -p "$(echo -e "${C_YELLOW}$prompt $options${C_RESET} "): " response
    response=${response:-$default}

    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Backup a file before modifying
backup_file() {
    local file="$1"
    local backup="${file}.bak.$(date +%s)"
    if [[ -f "$file" ]]; then
        cp "$file" "$backup"
        log_apply "INFO" "Backed up $file to $backup"
        echo -e "${C_BLUE}Backed up $file to $backup${C_RESET}"
    fi
}

# --- Specific Remediations ---

apply_fix_ssh_root() {
    echo -e "\n${C_BOLD}>>> Finding: SSH Root Login Enabled (INT-SSH-001)${C_RESET}"
    echo -e "Risk: High. Root login allows direct brute-force attacks on superuser."
    
    # Check for non-root sudoer
    # Simple check: search /etc/group for sudo/wheel users that are not root
    # This is rough but better than nothing.
    local sudoers=$(grep -E '^(sudo|wheel):' /etc/group | cut -d: -f4)
    local has_sudoer=0
    for user in ${sudoers//,/ }; do
        if [[ "$user" != "root" ]]; then
            has_sudoer=1
            echo -e "Detected sudoer user: ${C_GREEN}$user${C_RESET}"
        fi
    done

    if [[ $has_sudoer -eq 0 ]]; then
        echo -e "${C_RED}WARNING: No obvious non-root sudoer found in 'sudo' or 'wheel' groups.${C_RESET}"
        echo -e "Disabling root login might lock you out if you don't have another way in."
        if ! confirm_action "Do you REALLY want to disable PermitRootLogin?" "N"; then
            log_apply "SKIP" "Skipped disabling root login (No sudoer verified/User cancelled)"
            return
        fi
    else
        if ! confirm_action "Disable 'PermitRootLogin' in /etc/ssh/sshd_config?" "Y"; then
            log_apply "SKIP" "User skipped SSH Root Login fix"
            return
        fi
    fi

    local ssh_config="/etc/ssh/sshd_config"
    backup_file "$ssh_config"
    
    # Safe replacement
    if grep -q "^PermitRootLogin" "$ssh_config"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
    else
        echo "PermitRootLogin no" >> "$ssh_config"
    fi
    
    log_apply "SUCCESS" "Set PermitRootLogin no in $ssh_config"
    echo -e "${C_GREEN}Applied. Restart SSH service manually to take effect (systemctl restart ssh).${C_RESET}"
}

apply_fix_critical_ports() {
    echo -e "\n${C_BOLD}>>> Finding: Critical Internal Services Exposed (INT-NET-002)${C_RESET}"
    # Re-scan to find them alive
    if ! command -v ss &> /dev/null; then echo "Warning: 'ss' not found. Skipping."; return; fi
    
    # This regex must match the one in internal.sh/baseline.sh
    # Redis, Postgres, MySQL, Mongo, Elastic, Docker
    local ports_crit="^(6379|543[0-9]|3306|27017|9200|237[0-9])$"
    local raw_exposed=$(ss -lntu | awk '$5 !~ /^127\.0\.0\.1/ && $5 !~ /^\[::1\]/ && NR>1 {print $0}')

    while read -r line; do
        local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
        if [[ "$port" =~ $ports_crit ]]; then
            echo -e "\n${C_RED}${C_BOLD}>>> Critical Exposure Detected: Port $port${C_RESET}"
            echo "Evidence: $line"
            
            # Try to identify process
            local proc_info=""
            if [[ $EUID -eq 0 ]]; then
                proc_info=$(ss -lntp | grep ":$port" | awk '{print $6}')
                echo "Process: $proc_info"
            else
                echo "(Process name hidden: Run as root to see)"
            fi

            # Context-aware messaging
            case "$port" in
                6379)
                    echo -e "\n${C_YELLOW}Context: Redis (often Coolify/Docker)${C_RESET}"
                    echo " This service is likely intended for internal use only."
                    echo " Warning: Public exposure allows anyone to connect (if no auth) or brute-force."
                    echo " Recommendation: Block public access via firewall (Safe for containers)."
                    ;;
                5432|5433)
                    echo -e "\n${C_YELLOW}Context: PostgreSQL Database${C_RESET}"
                    echo " This may allow unauthenticated network access attempts or brute-force."
                    echo " Recommendation: Block public access via firewall (Safe)."
                    ;;
                2377)
                    echo -e "\n${C_RED}${C_BOLD}CRITICAL CONTEXT: Docker Swarm Management${C_RESET}"
                    echo " This port controls the cluster. Public exposure allows remote takeover."
                    echo " WARNING: This does not stop Docker, but restricts external access."
                    echo " Recommendation: Block public access via firewall IMMEDIATELY."
                    ;;
                *)
                    echo -e "\n${C_YELLOW}Context: Critical Internal Service${C_RESET}"
                    echo " This service should likely not be reachable from the internet."
                    ;;
            esac

            echo -e "\n${C_BOLD}Options:${C_RESET}"
            echo "1) Block public access via UFW (Recommended - Safe)"
            echo "2) Skip"
            
            read -p "Choose action [1/2]: " choice
            case "$choice" in
                1)
                    if command -v ufw &> /dev/null; then
                        echo "Executing: ufw deny $port"
                        ufw deny "$port" >/dev/null
                        log_apply "SUCCESS" "UFW denied port $port"
                        echo -e "${C_GREEN}Port $port blocked via UFW.${C_RESET}"
                    else
                        echo -e "${C_RED}Error: UFW not found. Install UFW or configure iptables manually.${C_RESET}"
                        log_apply "ERROR" "UFW not found for port $port"
                    fi
                    ;;
                *)
                    log_apply "SKIP" "Skipped port $port"
                    echo "Skipping."
                    ;;
            esac
        fi
    done <<< "$raw_exposed"
}

# apply_fix_writable_path Removed as per policy: 
# "NO debe tener fix" for World Writable PATH (complex/high risk of breakage on valid symlinks/custom setups).
# User should fix manually based on report.

# --- Main Apply Loop ---

run_apply() {
    echo -e "${C_BOLD}Starting Interactive Remediation${C_RESET}"
    echo -e "${C_YELLOW}WARNING: You are about to modify system configurations.${C_RESET}"
    echo -e "This tool will prompt for confirmation before every action."
    echo -e "A log will be saved to: $APPLY_LOG"
    echo ""
    
    init_apply_log

    # 1. SSH Root Fix
    apply_fix_ssh_root

    # 2. Critical Ports Fix
    apply_fix_critical_ports

    # 3. (Removed) Writable Path Fix
    # Users check manual report for INT-SYS-003

    echo ""
    echo "-------------------------------------"
    echo -e "${C_BOLD}Remediation Complete.${C_RESET}"
    echo "Please review $APPLY_LOG"
}

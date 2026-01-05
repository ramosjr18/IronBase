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
    
    # --- SSH Root Login Safety Check ---
    local sudoers=$(grep -E '^(sudo|wheel):' /etc/group | cut -d: -f4)
    local has_sudoer=0
    local sudo_user_list=""
    
    for user in ${sudoers//,/ }; do
        if [[ "$user" != "root" ]]; then
            has_sudoer=1
            sudo_user_list="$sudo_user_list $user"
        fi
    done

    if [[ $has_sudoer -eq 0 ]]; then
        echo -e "${C_RED}${C_BOLD}BLOCKING ACTION: No non-root sudoer user found.${C_RESET}"
        echo -e "Disabling root login without an alternative user WILL lock you out."
        echo -e "Action: ${C_RED}SKIPPING FIX (Safety Lock)${C_RESET}"
        log_apply "SKIP" "Refused to disable root login: No sudoers found."
        return
    else
        echo -e "Detected sudo users:${C_GREEN}$sudo_user_list${C_RESET}"
        echo "Action:"
        echo "1) Disable root SSH login (RECOMMENDED)"
        echo "2) Skip"
        
        read -p "Choose action [1/2]: " choice
        if [[ "$choice" != "1" ]]; then
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
    local raw_all=$(ss -lntu | awk '$5 !~ /^127\.0\.0\.1/ && $5 !~ /^\[::1\]/ && NR>1 {print $0}')
    local raw_critical=""
    local raw_unclassified=""

    # Split Critical vs Other
    while read -r line; do
        local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
        if [[ "$port" =~ $ports_crit ]]; then
            raw_critical+="${line}\n"
        else
            # Filter out Expected ports (Web/VoIP) to just find "Unclassified"
            local ports_expected="^(80|443|3478|7880|7881|22)$"
            if [[ ! "$port" =~ $ports_expected ]]; then
                raw_unclassified+="${line}\n"
            fi
        fi
    done <<< "$raw_all"

    # Handle Critical
    if [[ -n "$raw_critical" && "$raw_critical" != "\n" ]]; then
        while read -r line; do
            [[ -z "$line" ]] && continue
            local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
            
            echo -e "\n${C_RED}${C_BOLD}>>> Critical Exposure Detected: Port $port${C_RESET}"
            echo "Evidence: $line"
            
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
                    echo -e "\n${C_YELLOW}Context: Redis (likely Coolify/Docker)${C_RESET}"
                    echo " Recommendation: Block public access via firewall."
                    ;;
                5432|5433)
                    echo -e "\n${C_YELLOW}Context: PostgreSQL Database${C_RESET}"
                    echo " Recommendation: Block public access via firewall."
                    ;;
                2377)
                    echo -e "\n${C_RED}${C_BOLD}CRITICAL CONTEXT: Docker Swarm Management${C_RESET}"
                    echo " Recommendation: Block public access via firewall IMMEDIATELY."
                    ;;
                *)
                    echo -e "\n${C_YELLOW}Context: Critical Service${C_RESET}"
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
                        echo -e "${C_RED}Error: UFW not found.${C_RESET}"
                        log_apply "ERROR" "UFW not found for port $port"
                    fi
                    ;;
                *)
                    log_apply "SKIP" "Skipped port $port"
                    echo "Skipping."
                    ;;
            esac
        done <<< "$raw_critical"
    else
        echo "No Critical internal services exposed."
    fi

    # Handle Unclassified (INT-NET-001) - NO AUTO FIX
    if [[ -n "$raw_unclassified" && "$raw_unclassified" != "\n" ]]; then
        echo -e "\n${C_YELLOW}${C_BOLD}>>> Unclassified Services (INT-NET-001)${C_RESET}"
        echo "The following services are exposed but unclassified:"
        echo -e "$raw_unclassified"
        echo -e "${C_BOLD}Action: Manual Review Required.${C_RESET}"
        echo "These services require manual verification. No auto-fixes will be applied."
        log_apply "INFO" "Unclassified services listed for manual review."
    fi

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

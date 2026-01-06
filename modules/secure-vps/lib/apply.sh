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

    read -p "$(echo -e "${C_YELLOW}$prompt $options${C_RESET} "): " response < /dev/tty
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

    # Force Mode Bypass
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "${C_RED}${C_BOLD}FORCE MODE ACTIVE: Disabling Root Login (Ignoring Safety Locks)${C_RESET}"
        if [[ $has_sudoer -eq 0 ]]; then
            echo -e "${C_RED}WARNING: Check for sudo users FAILED. You may be LOCKED OUT after this.${C_RESET}"
        else
            echo -e "Confirmed sudo users:${C_GREEN}$sudo_user_list${C_RESET}"
        fi
    else
        # Normal Safety Logic
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
            
            read -p "Choose action [1/2]: " choice < /dev/tty
            if [[ "$choice" != "1" ]]; then
                log_apply "SKIP" "User skipped SSH Root Login fix"
                return
            fi
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
    
    log_apply "SUCCESS" "Set PermitRootLogin no in $ssh_config (Force=$IRONBASE_FORCE)"
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

    # Split Critical vs Other
    # Collect Critical RAW lines only first
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

    # Handle Critical (Deduplicated Logic)
    if [[ -n "$raw_critical" && "$raw_critical" != "\n" ]]; then
        # 1. Extract Unique Ports
        local ports_unique=$(echo -e "$raw_critical" | awk '{print $5}' | awk -F: '{print $NF}' | sort -u)
        
        # 2. Iterate per Logic Port
        for port in $ports_unique; do
            [[ -z "$port" ]] && continue
            
            echo -e "\n${C_RED}${C_BOLD}>>> Critical Exposure Detected: Port $port${C_RESET}"
            
            # Show all evidence for this port
            local evidence=$(echo -e "$raw_critical" | grep ":$port")
            echo "Evidence:"
            echo "$evidence"

            # Try to identify process (just once per port, usually sufficient context)
            local proc_info=""
            if [[ $EUID -eq 0 ]]; then
                proc_info=$(ss -lntp | grep ":$port" | head -n 1 | awk '{print $6}')
                echo "Process (Primary): $proc_info"
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

            # Action Prompt
            if [[ "$IRONBASE_FORCE" == "true" ]]; then
                 echo -e "\n${C_RED}${C_BOLD}FORCE MODE: Applying UFW Block Automatically${C_RESET}"
                 choice="1"
            else
                 echo -e "\n${C_BOLD}Options:${C_RESET}"
                 echo "1) Block public access via UFW (Recommended - Safe)"
                 echo "2) Skip"
                 read -p "Choose action [1/2]: " choice < /dev/tty
            fi
            
            case "$choice" in
                1)
                    if command -v ufw &> /dev/null; then
                        echo "Executing: ufw deny $port"
                        ufw deny "$port" >/dev/null
                        log_apply "SUCCESS" "UFW denied port $port (Force=$IRONBASE_FORCE)"
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
        done
    else
        echo "No Critical internal services exposed."
    fi

    # Handle Unclassified (INT-NET-001) - NO AUTO FIX EVEN IN FORCE MODE (As per rule: "NO aplicar fixes a findings sin remedicion definida")
    if [[ -n "$raw_unclassified" && "$raw_unclassified" != "\n" ]]; then
        echo -e "\n${C_YELLOW}${C_BOLD}>>> Unclassified Services (INT-NET-001)${C_RESET}"
        echo "The following services are exposed but unclassified:"
        echo -e "$raw_unclassified"
        echo -e "${C_BOLD}Action: Manual Review Required.${C_RESET}"
        echo "These services require manual verification. No auto-fixes will be applied."
        log_apply "INFO" "Unclassified services listed for manual review."
    fi
}

# apply_fix_writable_path Removed as per policy.

# --- Main Apply Loop ---

run_apply() {
    init_apply_log
    
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "\n${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!                  EMERGENCY HARDENING MODE (FORCE)                  !${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}WARNING: You have requested to FORCE apply all security fixes.${C_RESET}"
        echo -e "${C_RED}This will:${C_RESET}"
        echo -e "${C_RED}  - DISABLE internal safety locks (SSH root login check, etc.)${C_RESET}"
        echo -e "${C_RED}  - MODIFY critical configurations.${C_RESET}"
        echo -e "${C_RED}  - POTENTIALLY disrupt production services or SSH access.${C_RESET}"
        echo -e ""
        echo -e "This action is potentially disruptive and should only be used in emergencies"
        echo -e "or if you have console access/recovery options."
        echo -e ""
        echo -e "This will APPLY ALL security fixes without further confirmation."
        echo -e "Do you want to continue? (y/N): "
        
        read -p "Confirm FORCE execution (y/N): " force_confirm < /dev/tty
        if [[ ! "$force_confirm" =~ ^[Yy]$ ]]; then
            echo "Aborting Force Mode."
            log_apply "ABORT" "User aborted Force Mode at warning screen."
            return 1
        fi
        
        log_apply "FORCE_START" "User confirmed Force Mode execution."
        echo -e "${C_BOLD}>>> STARTING FORCED HARDENING <<<${C_RESET}"
    else
        # Normal Mode Header
        echo -e "${C_BOLD}Starting Interactive Remediation${C_RESET}"
        echo -e "${C_YELLOW}WARNING: You are about to modify system configurations.${C_RESET}"
        echo -e "This tool will prompt for confirmation before every action."
    fi

    echo -e "A log will be saved to: $APPLY_LOG"
    echo ""

    # 1. Critical Ports Fix (Highest Priority)
    # Order changed as requested: Firewall/Network first.
    apply_fix_critical_ports

    # 2. SSH Root Fix
    apply_fix_ssh_root

    # 3. (Removed) Writable Path Fix
    # Users check manual report for INT-SYS-003

    echo ""
    echo "-------------------------------------"
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "${C_RED}${C_BOLD}Forced Hardening Complete.${C_RESET}"
        echo "Mode: FORCE | Log saved at: $APPLY_LOG"
    else
        echo -e "${C_BOLD}Remediation Complete.${C_RESET}"
        echo "Please review $APPLY_LOG"
    fi
}

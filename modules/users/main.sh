#!/bin/bash

# modules/users/main.sh
# User and Privilege Checks

module_meta() {
    echo "Name: Users & Privileges"
    echo "Description: Checks UIDs, Sudoers, and Password policies."
    echo "Version: 1.0.0"
}

module_scan() {
    # 1. UID 0 Duplicates
    if [[ -f /etc/passwd ]]; then
        local uid0_users
        uid0_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
        local count
        count=$(echo "$uid0_users" | wc -l | xargs)
        
        if [[ "$count" -eq 1 ]]; then
             add_finding "USR-001" "$SEV_CRITICAL" "$STATUS_PASS" "UID 0 Users" \
                "Only one user with UID 0 found (root)." \
                "$uid0_users" \
                ""
        else
             add_finding "USR-001" "$SEV_CRITICAL" "$STATUS_FAIL" "UID 0 Users" \
                "Multiple users with UID 0 detected!" \
                "Users: $uid0_users" \
                "Remove unnecessary UID 0 accounts immediately."
        fi
    else
         add_finding "USR-001" "$SEV_CRITICAL" "$STATUS_WARN" "UID 0 Users" \
            "Cannot read /etc/passwd." \
            "" \
            "Check usage permissions."
    fi

    # 2. Users with Empty Passwords
    if [[ -f /etc/shadow ]] && [[ -r /etc/shadow ]]; then
        local empty_pw
        empty_pw=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
        if [[ -n "$empty_pw" ]]; then
            add_finding "USR-002" "$SEV_HIGH" "$STATUS_FAIL" "Empty Passwords" \
                "Users found with empty passwords." \
                "Users: $empty_pw" \
                "Lock accounts or set passwords."
        else
            add_finding "USR-002" "$SEV_HIGH" "$STATUS_PASS" "Empty Passwords" \
                "No users with empty passwords found." \
                "" \
                ""
        fi
    else
         # Often we can't read shadow as non-root user, so careful with WARN vs INFO
         if [ "$EUID" -ne 0 ]; then
            add_finding "USR-002" "$SEV_HIGH" "$STATUS_WARN" "Empty Passwords" \
                "Cannot read /etc/shadow (permission denied)." \
                "Run as root for full check." \
                ""
         fi
    fi

    # 3. Sudoers
    if [[ -f /etc/sudoers ]]; then
        if grep -q "NOPASSWD" /etc/sudoers; then
             add_finding "USR-003" "$SEV_HIGH" "$STATUS_WARN" "Sudoers NOPASSWD" \
                "Sudoers file contains NOPASSWD directives." \
                "grep NOPASSWD /etc/sudoers" \
                "Review sudoers file to ensure NOPASSWD is strictly limited."
        else
             add_finding "USR-003" "$SEV_HIGH" "$STATUS_PASS" "Sudoers NOPASSWD" \
                "No NOPASSWD directives found in /etc/sudoers." \
                "" \
                ""
        fi
    fi

    # 4. Check Root Password Integrity (is it locked?)
    # Typically root should be locked on Ubuntu (passwd -l root) which sets shell to nologin or pw to '!' or '*'
    if [[ -f /etc/shadow ]] && [[ -r /etc/shadow ]]; then
        local root_hash
        root_hash=$(grep "^root:" /etc/shadow | cut -d: -f2)
        if [[ "$root_hash" == "*" ]] || [[ "$root_hash" == "!"* ]]; then
            add_finding "USR-004" "$SEV_MEDIUM" "$STATUS_PASS" "Root Account Locked" \
                "Root account password is locked (standard for Ubuntu)." \
                "" \
                ""
        else
             add_finding "USR-004" "$SEV_MEDIUM" "$STATUS_INFO" "Root Account Locked" \
                "Root account has a valid password hash or is not strictly locked." \
                "" \
                "Ensure this is intentional."
        fi
    fi

    return 0
}

module_apply() {
    # No apply logic for this module check
    :
}

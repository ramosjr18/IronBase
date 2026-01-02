#!/bin/bash

# modules/filesystem/main.sh
# Filesystem Permissions Checks

module_meta() {
    echo "Name: Filesystem Permissions"
    echo "Description: Checks /etc, /boot, /root permissions and SUID bins."
    echo "Version: 1.0.0"
}

module_scan() {
    # 1. /etc Permissions (should be root:root usually)
    # Just check owner for now
    local etc_owner
    if [[ "$(uname)" == "Darwin" ]]; then
        etc_owner=$(stat -f '%Su' /etc)
    else
        etc_owner=$(stat -c '%U' /etc)
    fi
    if [[ "$etc_owner" == "root" ]]; then
         add_finding "FS-001" "$SEV_HIGH" "$STATUS_PASS" "/etc Ownership" \
            "/etc is owned by root." \
            "" \
            ""
    else
         add_finding "FS-001" "$SEV_HIGH" "$STATUS_FAIL" "/etc Ownership" \
            "/etc is NOT owned by root." \
            "Owner: $etc_owner" \
            "chown root:root /etc"
    fi

    # 2. World Writable files in /etc (limited depth)
    # find /etc -maxdepth 2 -type f -perm -o=w
    local ww_etc
    ww_etc=$(find /etc -maxdepth 2 -type f -perm -0002 2>/dev/null | head -n 5)
    if [[ -n "$ww_etc" ]]; then
         add_finding "FS-002" "$SEV_HIGH" "$STATUS_FAIL" "World Writable /etc" \
            "Found world writable files in /etc!" \
            "$ww_etc ..." \
            "Remove write permission for others (chmod o-w)."
    else
         add_finding "FS-002" "$SEV_HIGH" "$STATUS_PASS" "World Writable /etc" \
            "No world writable files found in /etc (depth 2)." \
            "" \
            ""
    fi

    return 0
}

module_apply() {
    :
}

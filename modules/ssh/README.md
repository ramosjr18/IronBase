# SSH Hardening Module

A focused, robust hardening module for OpenSSH configuration. This module provides a safe, interactive wizard to harden SSH access, create sudo users, and disable root login without risk of lockout.

## Features

*   **Diagnostic Scan**: Instantly audits `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, and existing User/Sudo privileges.
*   **Interactive Wizard**: Guides you step-by-step through:
    *   Replacing root access with a new user.
    *   Creating new regular or sudo users.
    *   Verifying user creation and password setting before applying changes.
*   **Safe-by-Default**:
    *   Never disables root login without explicit confirmation *and* successful user verification.
    *   Uses backups for all configuration changes.
*   **Standalone Capable**: Can run independently of the full IronBase engine.

## Usage

### Integrated Mode (IronBase)

```bash
# 1. Scan (Audit Configuration)
./cmd/ironbase scan --module ssh

# 2. Apply (Launch Hardening Wizard)
./cmd/ironbase apply --module ssh
```

### Standalone Mode

Run independently on any system:

```bash
# Scan
./modules/ssh/standalone.sh

# Apply (Interactive Wizard)
./modules/ssh/standalone.sh apply
```

## Hardening Wizard Flow

1.  **Context Analysis**: Checks if Root Login is enabled and if any other sudo users exist.
2.  **Strategy Selection**:
    *   **Option 1: Replace Root**. Creates a new sudo user, validates it, and prompts to disable root login.
    *   **Option 2: Add User**. Creates a new user but keeps root login enabled (for gradual migration).
    *   **Option 3: Review**. Exits without changes.
3.  **Verification**: Before disabling root, the wizard verifies the potential new entry point exists and has sudo rights.
4.  **Logging**: All actions are logged to `ssh-apply.log`.

## Relationship with `secure-vps`

This module (`ssh`) is the core SSH hardening logic provider. The `secure-vps` module imports the logic from here, ensuring consistent behavior across both modules.

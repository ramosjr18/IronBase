# Filesystem Permissions Module

## Overview

**⚠️ DEVELOPMENT STATUS: This module is currently in development and should be used at your own risk.**

This module checks critical filesystem permission configurations on Linux systems. It verifies ownership and world-writable permissions for sensitive directories (`/etc`, `/boot`, `/root`) and files. These checks are fundamental for preventing unauthorized modifications to system configuration files.

**Context**: Use this module to audit basic filesystem security posture before deploying hardening changes. This is a baseline check that should run early in any security assessment.

**⚠️ WARNING**: This module is incomplete. The `apply` functionality is not implemented. Only `scan` mode is currently functional. Use with caution.

## What This Module Does (Current Capabilities)

- **FS-001**: Verifies `/etc` directory ownership (must be `root`)
- **FS-002**: Detects world-writable files in `/etc` (maxdepth 2, limited scope)

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **FS-001** | HIGH | PASS/FAIL | `/etc` ownership check (must be root) |
| **FS-002** | HIGH | PASS/FAIL | World-writable files in `/etc` (limited depth) |

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT check `/boot` or `/root` permissions** (metadata mentions these but code does not implement)
- **Does NOT verify SUID binaries** (metadata mentions this but code does not implement)
- **Does NOT check permissions recursively** (only checks maxdepth 2 in `/etc`)
- **Does NOT verify file permissions** (only checks world-writable flag, not full permission modes)
- **Does NOT scan other sensitive directories** (`/var/log`, `/tmp`, `/home`, etc.)
- **Does NOT detect setuid/setgid files**
- **Does NOT verify sticky bits**
- **Does NOT check for misconfigured sudo executables**
- **Does NOT provide apply/remediation functionality** (scan-only module)

## Scan Behavior

When executing `ironbase scan --module filesystem`:

1. Checks `/etc` directory ownership using `stat` (cross-platform: supports both Linux and macOS stat syntax)
2. Scans `/etc` for world-writable files (maxdepth 2, non-recursive)
3. Reports findings with evidence (owner name, file paths)
4. Returns exit code 0 (always passes, findings reported via status)

**Output**: Findings are displayed on console and registered to global report. No files are modified.

**Exit Code**: Always returns 0 (scan completes successfully even if issues found)

## Apply Behavior

**Not Applicable**: This module does not implement `module_apply()`. The function exists but is a no-op (`:`).

All remediation must be performed manually:
- Fix ownership: `sudo chown root:root /etc`
- Remove world-writable: `sudo chmod o-w <file>`

## Safety Notes

- **Read-only operation**: This module only reads filesystem metadata. No modifications are performed.
- **No lockout risk**: Scanning filesystem permissions cannot cause system lockout or access issues.
- **May require root**: Reading `/etc/shadow` equivalent checks would require root, but current implementation does not access protected files.
- **Cross-platform**: Supports both Linux and macOS (handles different `stat` command syntax)

**When NOT to use**: This module is designed for Linux systems. On macOS, only basic checks will function correctly.

## Usage Examples

### Basic Scan

```bash
./cmd/ironbase scan --module filesystem
```

### Integrated with Profile

```bash
# Run all modules in profile (includes filesystem if enabled)
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Expected Output

```
[PASS] [HIGH] /etc Ownership (FS-001)
[PASS] [HIGH] World Writable /etc (FS-002)
      Description: No world writable files found in /etc (depth 2).
```

## Status

**State**: ⚠️ **IN DEVELOPMENT** - Use at your own risk

**⚠️ IMPORTANT**: This module is currently in development. Only scan functionality is implemented. Apply mode is not available and will not perform any actions.

**Features Implemented**:
- `/etc` ownership verification
- World-writable file detection (limited depth)

**Features Pending**:
- `/boot` and `/root` permission checks (mentioned in metadata, not implemented)
- SUID binary scanning (mentioned in metadata, not implemented)
- Recursive permission checking
- Full permission mode analysis
- Apply/remediation functionality (NOT IMPLEMENTED)
- Additional sensitive directory checks

**⚠️ DISCLAIMER**: This module is provided as-is for experimental use. The scan functionality is stable, but the module is incomplete and should not be used in production environments without thorough testing.

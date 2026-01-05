# Secure VPS Module (secure-vps)

A self-contained security assessment module for public Linux VPS environments. This module evaluates the security posture from both an **Internal** (Host-based) and **External** (Network-based simulation) perspective.

## Features

*   **Dual-Perspective Scanning**:
    *   **Internal**: Checks kernel version, OS hardening, exposed internal services, SSH configuration, and system anomalies.
    *   **External**: Simulates network exposure checks (Open ports, Public IP, SSH default port).
*   **Structured Findings**: Categorizes findings by Severity (Critical to Info), Type (Vuln, Risk, Misconfig), and Origin.
*   **Actionable Reporting**: Provides clear **Recommendations** and **Evidence** for every finding.
*   **Auto-generated Report**: Saves a full detail report to `secure-vps-scan.txt` after every run.

## Usage

### Integrated Mode (IronBase)
Run as part of the IronBase suite:

```bash
# 1. Scan (Read-Only)
./cmd/ironbase scan --module secure-vps

# 2. Apply (Interactive - Safe by Default)
./cmd/ironbase apply --module secure-vps

# 3. Apply Force (EMERGENCY ONLY)
# WARNING: Bypasses safety checks. Use only with console access.
./cmd/ironbase apply --module secure-vps --force
```

### Standalone Mode
Run independently without the full IronBase engine:

```bash
git sparse-checkout set modules/secure-vps

# Scan
./modules/secure-vps/standalone.sh

# Apply (Interactive)
./modules/secure-vps/standalone.sh apply

# Apply (Force)
./modules/secure-vps/standalone.sh --force
```

## Hardening Modes

| Mode | Flag | Description | Safety |
| :--- | :--- | :--- | :--- |
| **Scan** | `scan` | Read-only assessment. | Non-destructive. |
| **Apply** | `apply` | Interactive remediation. Prompts for every change. Backups enabled. | High. Prevents lockout. |
| **Force** | `--force` | **Unsafe execution**. Bypasses prompts and locks. | **Low**. Use for emergency hardening. |

> [!WARNING]
> **Force Mode** (`--force`) will strictly apply all security rules. It may disable SSH Root login even if no alternative user is found, potentially locking you out. **Always ensure you have VNC/Console access before using this mode.**

## Report Output

Every execution generates a report file: `secure-vps-scan.txt` in the current working directory.
This file contains:
- Executive Summary
- Full Findings Details (including non-truncated evidence)
- Next Steps

## Severity & Classification

| Severity | Description |
| :--- | :--- |
| **CRITICAL** | Immediate threat to system compromise (e.g. Empty Passwords, Root exposed services). |
| **HIGH** | Significant risk (e.g. EOL Kernel, World Writable PATH). |
| **MEDIUM** | Moderate risk or standard hardening gap (e.g. Unknown ports listening). |
| **LOW** | Best practice deviation (e.g. Legacy but supported kernel). |
| **INFO** | informational finding (e.g. Public IP detection). |

## Internal Service Classification

The module automatically classifies listening ports:
*   **Critical**: Databases and Management interfaces (Redis, MySQL, Docker) exposed to 0.0.0.0.
*   **Expected**: Web (80/443) and VoIP (3478/7880).
*   **Unclassified**: Any other service listening globally is flagged as MEDIUM risk.

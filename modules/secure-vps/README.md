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
# Scan
./cmd/ironbase scan --module secure-vps

# Apply Fixes (Interactive Mode - Safe)
./cmd/ironbase apply --module secure-vps
```

### Standalone Mode
Run independently without the full IronBase engine:

```bash
git sparse-checkout set modules/secure-vps
# Scan
./modules/secure-vps/standalone.sh

# Apply
./modules/secure-vps/standalone.sh apply
```

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

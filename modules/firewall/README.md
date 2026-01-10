# Firewall Hardening Module

A comprehensive UFW (Uncomplicated Firewall) auditing and hardening module for IronBase. This module performs baseline configuration checks and advanced scan-only assessments of firewall rules, interference detection, and service exposure correlation.

## Features

*   **Baseline Checks**: Verifies UFW installation, active status, and default policies
*   **Advanced Scanning**: 11 comprehensive checks covering rule completeness, interference, and exposure
*   **Fail-Fast Behavior**: Stops scanning if UFW is not installed or inactive (FW-001/FW-002)
*   **Service Correlation**: Correlates listening services with firewall rules to detect exposure gaps
*   **Interference Detection**: Identifies Docker, multiple firewalls, and forwarding issues

## Usage

### Integrated Mode (IronBase)

```bash
# Scan firewall configuration
./cmd/ironbase scan --module firewall

# Apply (Currently mockeado - no funcional)
./cmd/ironbase apply --module firewall
```

## Scan Behavior

### Fail-Fast Design

**Important**: This module implements fail-fast behavior for critical prerequisites:

1. **FW-001 (UFW Installed)**: If UFW is not installed, the scan **stops immediately** after reporting FW-001 and returns exit code 1. No further checks are performed.

2. **FW-002 (UFW Status)**: If UFW is inactive, the scan **stops immediately** after reporting FW-002 and returns exit code 1. Advanced checks (FW-004 through FW-011) are **not executed**.

**Rationale**: Advanced firewall checks (rule analysis, service correlation, interference detection) are only meaningful when UFW is installed and active. Running these checks against an inactive firewall would produce misleading or irrelevant results.

**If UFW is inactive, the firewall scan stops after FW-002.** This demonstrates intentional design maturity and prevents false positives from advanced checks.

## Scan Checks

### Baseline Checks (FW-001 to FW-003)

| ID | Severity | Check | Description |
|:---|:---------|:-----|:------------|
| **FW-001** | HIGH | UFW Installed | Verifies UFW package is installed. **Fail-fast**: Stops scan if missing. |
| **FW-002** | HIGH | UFW Status | Verifies UFW is active. **Fail-fast**: Stops scan if inactive. |
| **FW-003** | MEDIUM/HIGH | Default Incoming Policy | Verifies default incoming policy is DENY. |

### Advanced Checks (FW-004 to FW-011)

These checks **only execute if UFW is active** (FW-002 passed):

| ID | Severity | Check | Description |
|:---|:---------|:-----|:------------|
| **FW-004** | HIGH/MEDIUM | Specific Allow Rules Exist | Detects explicit ALLOW IN rules. Verifies SSH port is allowed if listening. |
| **FW-005** | MEDIUM/LOW | Docker / nftables Interference | Detects Docker service and DOCKER chains. Warns if bypass potential exists. |
| **FW-006** | HIGH/MEDIUM | Multiple Firewalls Active | Detects ufw, firewalld, nftables, and manual iptables. FAILs if multiple active. |
| **FW-007** | HIGH/MEDIUM | Real Service Exposure (Correlated) | Parses listening services and correlates with UFW rules. FAILs if services exposed without firewall control. |
| **FW-008** | HIGH/MEDIUM/LOW | Forwarding / NAT Policy | Checks IPv4/IPv6 forwarding and UFW routed policies. FAILs if forwarding enabled without firewall intent. |
| **FW-009** | MEDIUM/LOW | Logging & Rate Limiting | Verifies UFW logging status and detects `limit` rules. Warns if logging off and no rate-limit. |
| **FW-010** | HIGH/MEDIUM | IPv6 Enforcement | Verifies IPV6=yes in /etc/default/ufw and IPv6 rules presence. FAILs if IPv6 disabled/unenforced. |
| **FW-011** | MEDIUM/LOW/INFO | Configuration Drift | Compares listening ports vs UFW allow rules. Warns if services listening without corresponding firewall rules. |

## Example Output

### UFW Inactive (Fail-Fast Behavior)

```bash
$ ./cmd/ironbase scan --module firewall
[INFO] Running module: Firewall Hardening (firewall)
[FAIL] [HIGH] UFW Status (FW-002)
      Description: UFW is inactive. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness.
      Remediation: Run 'ufw enable'

[WARN] Module Firewall Hardening: FAILED/ISSUES FOUND
```

**Note**: No advanced checks (FW-004 through FW-011) are executed. The scan stops after FW-002.

### UFW Active (Full Scan)

```bash
$ ./cmd/ironbase scan --module firewall
[INFO] Running module: Firewall Hardening (firewall)
[PASS] [HIGH] UFW Status (FW-002)
[PASS] [MEDIUM] Default Incoming Policy (FW-003)
[PASS] [MEDIUM] Specific Allow Rules Exist (FW-004)
[WARN] [MEDIUM] Docker / nftables Interference (FW-005)
      ...
[OK] Module Firewall Hardening: PASSED
```

All checks (FW-001 through FW-011) are executed when UFW is active.

## Module Apply Status

⚠️ **Currently Non-Functional**: The `module_apply()` function is mocked (commented out). All remediation steps must be performed manually based on scan findings.

Future implementation will include:
- UFW installation (if missing)
- UFW activation with confirmation
- Default policy configuration
- Rule management with backups

## Exit Codes

- `0`: All checks passed OR medium/low findings only (acceptable state)
- `1`: High/Critical findings detected OR UFW missing/inactive (fail-fast)

## Relationship with Other Modules

- **`network`**: Firewall module checks service exposure that network module detects
- **`secure-vps`**: Uses UFW status contextually for port mitigation checks
- **`services`**: Firewall checks Docker interference (service detection)

## Design Philosophy

This module demonstrates **defensive programming** and **explicit failure modes**:

1. **Fail-Fast**: Critical prerequisites must be met before advanced checks
2. **Conservative Findings**: Only reports what can be verified (no speculation)
3. **Clear Intent**: Behavior is documented and predictable
4. **Scan-Only**: No system changes during scan mode

## References

- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [IronBase Architecture](docs/ARCHITECTURE.md)
- [Scanners Reference](SCANNERS.md)

# IronBase Scanners & Features

This document details the scanning capabilities embedded in IronBase, explaining the types of scans available, the specific checks performed, and the meaning of the findings they generate.

## Overview

IronBase employs a multi-layered scanning approach to identify vulnerabilities, misconfigurations, and exposure risks. The scanners are divided into module-specific categories, primarily focusing on **System/Internal** security and **Network/External** exposure.

## Scan Types

### 1. Internal Scan (Host-Based)
**Focus**: Inspects the local system configuration, file permissions, kernel state, and running services from "inside" the server.
**Goal**: Identify weak configurations, legacy software, and potential privilege escalation vectors.
**Modules Involved**: `secure-vps`, `ssh`

### 2. External Scan (Network Simulation)
**Focus**: Simulates how an attacker views the server from the internet.
**Goal**: Detect exposed services, public ports, and potential attack surfaces visible to the outside world.
**Note**: This scan runs locally but uses logic to determine what interfaces are public.
**Modules Involved**: `secure-vps`

---

## Detailed Features & Findings

The following table details the specific checks performed by the scanners, their IDs, and what they signify.

### System & Kernel (Internal)

| Finding ID | Severity | Check Description | Meaning & Risk |
| :--- | :--- | :--- | :--- |
| **INT-SYS-001** | High/Low/Info | **Kernel Version Check** | Analyzes the running kernel version. <br>• **High**: EOL kernel (< 4.19). Vulnerable to exploits.<br>• **Low**: Legacy but supported (4.x, 5.0-5.14).<br>• **Info**: Modern kernel (OK). |
| **INT-SYS-002** | High | **ASLR Status** | Checks Address Space Layout Randomization. <br>• **Risk**: If disabled/weak, memory corruption exploits are easier. |
| **INT-SYS-003** | High | **World Writable PATH** | Checks if any directory in `$PATH` is writable by everyone. <br>• **Risk**: Privilege escalation (attackers can hijack commands). |

### User & Authentication (Internal)

| Finding ID | Severity | Check Description | Meaning & Risk |
| :--- | :--- | :--- | :--- |
| **INT-USR-001** | **Critical** | **Multiple UID 0 Users** | Checks for users other than `root` with UID 0. <br>• **Risk**: Backdoors or unauthorized root-level accounts. |
| **INT-USR-002** | **Critical** | **Empty Passwords** | Checks `/etc/shadow` for accounts with no password. <br>• **Risk**: Unrestricted access to accounts. |
| **INT-SSH-001** | High | **SSH Root Login** | Checks `PermitRootLogin` in `sshd_config`. <br>• **Risk**: Brute-force attacks targeting the known `root` user. |
| **INT-SSH-002** | Medium | **SSH Password Auth** | Checks `PasswordAuthentication` in `sshd_config`. <br>• **Risk**: Password guessing/brute-force acts. Keys are recommended. |

### Network & Services (Internal & External)

| Finding ID | Severity | Check Description | Meaning & Risk |
| :--- | :--- | :--- | :--- |
| **EXT-NET-000** | Info | **Public IP Detection** | Confirms if the server has a detectable public IP. |
| **EXT-NET-002** | High | **Ports Exposed to Internet** | Detects services listening on `0.0.0.0` or public IP. <br>• **Risk**: Services accessible by anyone on the internet. |
| **EXT-NET-003** | Low | **ICMP Echo (Ping)** | Checks if server replies to ping. <br>• **Risk**: Makes server discoverable by scanners (low risk). |
| **EXT-SSH-001** | Medium | **SSH on Port 22** | Checks if SSH is on default port 22 and exposed. <br>• **Risk**: High volume of automated brute-force "noise". |
| **INT-NET-002** | **Critical** | **Critical Internal Services** | *Verified Exposure*. Checks for internal DBs (Redis, MySQL, Mongo) listening publicly without firewall blocks. <br>• **Risk**: Data leak or remote code execution. |
| **INT-NET-002-M**| Info | **Mitigated Services** | Services listening publicly but **blocked by UFW/Firewall**. <br>• **Meaning**: Safe, but binding to localhost is cleaner. |
| **INT-NET-003** | Info | **Expected Services** | Web ports (80, 443) or VoIP ports open. <br>• **Meaning**: Standard operation for a web/app server. |
| **INT-NET-001** | Medium | **Unclassified Services** | Any other service listening publicly not in the allowlist. <br>• **Risk**: Potential unknown exposure. |

### Firewall (UFW-based)

| Finding ID | Severity | Check Description | Meaning & Risk |
|:---|:---------|:------------------|:---------------|
| **FW-001** | High | **UFW Installed** | Verifies UFW package is installed. <br>• **Fail-Fast**: Scan stops if UFW not installed. |
| **FW-002** | High | **UFW Status** | Verifies UFW is active. <br>• **Fail-Fast**: **If UFW is inactive, the firewall scan stops after FW-002.** Advanced checks (FW-004 through FW-011) are not executed. |
| **FW-003** | Medium/High | **Default Incoming Policy** | Verifies default incoming policy is DENY. <br>• **Risk**: If not DENY, services may be exposed unintentionally. |
| **FW-004** | High/Medium | **Specific Allow Rules Exist** | Detects explicit ALLOW IN rules. Verifies SSH port is allowed if listening. <br>• **Risk**: Default deny with no allow rules may lock out legitimate access. |
| **FW-005** | Medium/Low | **Docker / nftables Interference** | Detects Docker service and DOCKER chains. Warns if bypass potential exists. <br>• **Risk**: Docker may bypass UFW rules, exposing ports unintentionally. |
| **FW-006** | High/Medium | **Multiple Firewalls Active** | Detects ufw, firewalld, nftables, and manual iptables. <br>• **Risk**: Multiple firewalls can conflict, causing unpredictable behavior. |
| **FW-007** | High/Medium | **Real Service Exposure (Correlated)** | Parses listening services and correlates with UFW rules. <br>• **Risk**: Services listening on public interfaces without firewall control are exposed to internet. |
| **FW-008** | High/Medium/Low | **Forwarding / NAT Policy** | Checks IPv4/IPv6 forwarding and UFW routed policies. <br>• **Risk**: Forwarding enabled without firewall intent may expose internal networks. |
| **FW-009** | Medium/Low | **Logging & Rate Limiting** | Verifies UFW logging status and detects `limit` rules. <br>• **Risk**: Without logging or rate limits, brute-force attacks may go undetected. |
| **FW-010** | High/Medium | **IPv6 Enforcement** | Verifies IPV6=yes in /etc/default/ufw and IPv6 rules presence. <br>• **Risk**: If IPv6 is enabled system-wide but UFW IPv6 is disabled, IPv6 traffic bypasses firewall. |
| **FW-011** | Medium/Low/Info | **Configuration Drift** | Compares listening ports vs UFW allow rules. <br>• **Risk**: Services listening without corresponding firewall rules indicate configuration drift. |

**Important Fail-Fast Behavior**: 
- **FW-001**: If UFW is not installed, scan stops immediately (returns exit code 1).
- **FW-002**: If UFW is inactive, scan stops immediately after reporting FW-002 (returns exit code 1). Advanced checks (FW-004 through FW-011) are **not executed**.
- **Rationale**: Advanced firewall checks are only meaningful when UFW is installed and active. This prevents misleading results from checks that require an active firewall.

## How to Run Scanners

Scanners are typically executed as part of the module workflows (e.g., specific flags in wizards), but can often be invoked via the core engine logic or specific module entry points.

*   **Secure VPS Module**: Runs comprehensive Internal + External scans.
*   **SSH Module**: Runs focused SSH configuration scans (3 checks: PermitRootLogin, PasswordAuth, PermitEmptyPasswords).
*   **Firewall Module**: Runs UFW baseline and advanced checks (11 checks total, fail-fast on prerequisites).

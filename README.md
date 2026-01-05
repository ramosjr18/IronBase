# IronBase

> **A Modular, Future-Proof Linux Hardening Engine.**

IronBase is designed to be the foundational layer for secure Linux system configuration. It separates hardening logic (modules) from orchestration (core), allowing for scalable, safe, and auditable system hardening.

## Features

-   **Modular Architecture**: Hardening rules are isolated in self-contained modules.
-   **Safe Defaults**: "Scan" mode is read-only and non-destructive.
-   **Profile Based**: Define your security posture in simple YAML profiles.
-   **Future Ready**: Architected to evolve from formatted Bash scripts to a compiled high-performance binary without breaking contracts.

## Quick Start

### 1. Scan your system
Run a non-destructive scan to see your current security posture:
```bash
./cmd/ironbase scan
```

### 2. Apply hardening (Simulation)
Apply the baseline Ubuntu profile:
```bash
./cmd/ironbase apply
```

### 3. Scan a specific module
```bash
# SSH Hardening
./cmd/ironbase scan --module ssh

# Secure VPS (Comprehensive Assessment)
./cmd/ironbase scan --module secure-vps
```

## Available Modules

### `secure-vps`
A self-contained module for assessing and securing public VPS instances.
- **Internal Analysis**: Kernel, Users, SSH, Services, Permissions.
- **External Simulation**: Exposure check, Public IP, Critical Ports.
- **Safe Remediation**: Interactive `apply` mode with backups and safety locks.
- **Reporting**: Generates a detailed `secure-vps-scan.txt` report.

```bash
# Run Interactive Fixes
./cmd/ironbase apply --module secure-vps

# Run Simulated Emergency Fixes (Force Mode)
# WARNING: This bypasses safety checks and applies all fixes automatically.
# Use only if you have console access or recovery options.
./cmd/ironbase apply --module secure-vps --force
```


## Documentation

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a deep dive into the design philosophy and internal contracts.
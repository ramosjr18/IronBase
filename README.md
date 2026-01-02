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
./cmd/ironbase scan --module ssh
```

## Documentation

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a deep dive into the design philosophy and internal contracts.
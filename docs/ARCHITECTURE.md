# IronBase v0 Architecture

## Vision
IronBase is a modular, future-proof Linux hardening engine. While v0 is implemented in Bash for portability and rapid prototyping, its architecture is designed from the ground up to support a future port to compiled languages (Go or Rust) without changing internal contracts or user experience.

## key Principles
1.  **Modularity**: Hardening logic is isolated in "modules". The core engine doesn't know about specific hardening rules.
2.  **Idempotency**: All operations (scan/apply) should be safe to run multiple times.
3.  **Observability**: structured output (JSON/YAML friendly logs) for easy parsing by future GUI/web layers.
4.  **Safety**: "Scan" is read-only. "Apply" is opt-in.

## System Components

### 1. The Core Engine (`core/`)
The brain of IronBase. It is responsible for:
-   **Orchestration**: Loading modules and executing them in the correct order.
-   **Configuration**: Parsing the profile (`ubuntu-baseline.yaml`) to determine which modules are enabled.
-   **Reporting**: Aggregating results from modules into a unified report.

### 2. Modules (`modules/`)
Self-contained units of hardening logic.
Each module must implement the following "contract" (interface):

-   **`module_meta`**: Returns metadata (Name, Description, Risk Level).
-   **`module_scan`**: Checks the file system or configuration. Returns `PASS` or `FAIL` with details. **Must not modify the system.**
-   **`module_apply`**: Enforces the hardening rule. **Should checks if it's already applied first.**

**Directory Structure per Module:**
```
modules/
  └── <module_name>/
      └── main.sh  # Entry point implementing the contract
```

### 3. Profiles (`profiles/`)
YAML files that define the desired state.
Example:
```yaml
modules:
  ssh:
    enabled: true
  firewall:
    enabled: true
    port_allow: [22, 80, 443]
```

### 4. Interfaces
-   **CLI** (`cmd/ironbase`): The primary interface for v0.
-   **GUI** (`ui/`): Placeholder for future graphical frontends. The architecture ensures the GUI just calls the Core Engine or parses its output, rather than containing hardening logic itself.

## Future Evolution Path

-   **Phase 1 (Now)**: Bash-based architecture, CLI only.
-   **Phase 2**: Port `core/` to Go. Modules can remain in Bash (executed by Go) or be rewritten in Go.
-   **Phase 3**: Add a REST API or gRPC layer on top of `core/` for remote management.
-   **Phase 4**: Build a React/Tauri GUI that consumes the API.

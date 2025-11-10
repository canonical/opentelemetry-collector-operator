# OpenTelemetry Collector Operator - AI Coding Guide

## Project Overview

This is a **Juju charm** (operator) for deploying OpenTelemetry Collector on machines (LXD, MAAS). It's a **subordinate charm** that attaches to principal applications to collect telemetry (logs, metrics, traces, profiles) and forward to observability backends.

**Key architectural decisions:**
- **Subordinate model**: This charm deploys alongside principal applications via `juju-info` or `cos-agent` relations (defined in `charmcraft.yaml`). Multiple principals can share a single OTel Collector snap instance.
- **Singleton snap management**: Uses file-based locking (`src/singleton_snap.py`) to coordinate snap installations across multiple units sharing the same machine, preventing conflicts when multiple subordinate units try to manage the same snap.
- **Hook-based lifecycle**: The charm follows a specific hook sequence (`install`/`upgrade` → `_reconcile()` on most hooks → `remove`). The reconciler pattern (`_reconcile()`) rebuilds configuration on every hook except install/upgrade/remove.
- **MandatoryRelationPairs**: The charm enforces relation pair requirements (e.g., `cos-agent` must pair with at least one outgoing relation like `send-remote-write`) to prevent data loss scenarios. See `_get_missing_mandatory_relations()` in `src/charm.py`.

## Architecture Components

### Core Configuration System
- **`ConfigBuilder`** (`src/config_builder.py`): Low-level builder for OTel Collector YAML config (receivers, processors, exporters, pipelines).
- **`ConfigManager`** (`src/config_manager.py`): High-level abstraction wrapping ConfigBuilder with feature-oriented methods like `add_traces_forwarding()`, `add_log_forwarding()`, `add_prometheus_scrape()`.
- Configuration is written per-unit to `/etc/otelcol/config.d/<unit_name>.yaml` (sanitized via `SnapRegistrationFile._normalize_name()`).

### Snap Management
- **`SnapMap`** (`src/snap_management.py`): Hardcoded mapping of snap names → revisions by architecture/confinement. Update when upgrading snaps.
- **`SingletonSnapManager`** (`src/singleton_snap.py`): Manages exclusive access using lock files in `/opt/singleton_snaps`. Each unit registers/unregisters when using a snap revision.
- **`SnapFstab`** (`src/snap_fstab.py`): Parses `/var/lib/snapd/mount/snap.opentelemetry-collector.fstab` to discover log file mounts from principals (via snap content interfaces).

### Integration Layer (`src/integrations.py`)
Handles all relation data exchanges using charm libraries from `lib/charms/`:
- **COS Agent**: Scrapes metrics jobs, collects logs via snap content interfaces (`snap_log_endpoints`), aggregates alerts/dashboards.
- **Tracing**: `receive-traces` (ingress), `send-traces` (egress to Tempo), `send-charm-traces` (separate for charm tracing).
- **Profiling**: `receive-profiles`/`send-profiles` for continuous profiling data (Pyroscope).
- **TLS**: `receive-ca-cert` (install trusted CAs), `receive-server-cert` (obtain server cert for incoming TLS).
- **Remote Write**: `send-remote-write` (metrics), `send-loki-logs` (logs), `cloud-config` (Grafana Cloud).

## Development Workflow

### Setup
```bash
tox devenv -e integration  # Creates venv with all deps
source venv/bin/activate
```

### Testing
```bash
tox run -e fmt        # Auto-format code
tox run -e lint       # Ruff linting
tox run -e static     # Pyright type checking
tox run -e unit       # Unit tests (uses Scenario/Context framework)
tox run -e integration # Integration tests (uses pytest-operator + jubilant)
tox                   # Runs fmt, lint, static, unit
```

**Unit testing pattern** (`tests/unit/`):
- Uses `ops.testing.Context` (Scenario framework) for isolated charm testing.
- Mock external dependencies in `conftest.py` fixtures (e.g., `patch("charm.refresh_certs")`).
- Configuration files are tested by reading from temp directories (see `config_folder` fixture).
- Example: `test_config_manager.py` validates OTel config structure without deploying.

**Integration testing pattern** (`tests/integration/`):
- Uses `jubilant` for declarative Juju model management (see `conftest.py` fixtures).
- Tests deploy real charms (e.g., `zookeeper`) and verify telemetry collection via snap logs.
- Charm packing modifies internal telemetry log level (see `change_text_in_file` in `conftest.py`) for observability during tests.

### Building
```bash
charmcraft pack  # Produces .charm file (multi-base support: 22.04, 24.04)
```

## Project-Specific Conventions

### Hook Lifecycle
1. **`install`/`upgrade`**: Call `_install_snaps()` to install opentelemetry-collector and node-exporter snaps, then exit.
2. **All other hooks**: Call `_reconcile()` which rebuilds the entire config and restarts services.
3. **`remove`**: Call `_remove_node_exporter()` and `_remove_opentelemetry_collector()`, then exit immediately. Do NOT reconcile on remove to avoid peer relation data causing reconciliation loops.

### Relation Data Handling
- **Peer relation** (`peers`): Used by COS Agent library to aggregate alerts/dashboards across units. Only leader processes aggregated data.
- **Subordinate scope**: Relations like `cos-agent` and `juju-info` use `scope: container` to pair with principal units on the same machine.
- **Mandatory pairing**: Use `MandatoryRelationPairs` (from `cosl`) to validate that incoming relations (like `cos-agent`) are paired with outgoing relations (like `send-remote-write`). Otherwise, set `BlockedStatus`.

### Configuration Validation
- **Global scrape configs**: Must match regex `^\d+[ywdhms]$` (e.g., `30s`, `5m`). See validation in `_reconcile()`.
- **Tracing sampling rates**: Config options `tracing_sampling_rate_charm`, `tracing_sampling_rate_workload`, `tracing_sampling_rate_error` (0-100%) feed into tail sampling processor.
- **TLS**: Check `is_tls_ready()` before enabling TLS receivers. Certs are expected at `SERVER_CERT_PATH` and `SERVER_CERT_PRIVATE_KEY_PATH`.

### File Paths and Naming
- Unit name normalization: Use `SnapRegistrationFile._normalize_name(unit_name)` to convert `otelcol/0` → `otelcol_0` for filenames.
- Config directory: `/etc/otelcol/config.d/` contains per-unit YAML files.
- Snap common dir: `/var/snap/opentelemetry-collector/common/` for file storage extensions.
- Lock directory: `/opt/singleton_snaps/` for singleton snap registration files (format: `LCK..<snap>__rev<revision>__<unit>`).

### Charm Libraries (`lib/charms/`)
- These are versioned libraries from other charms (e.g., `prometheus_k8s`, `tempo_coordinator_k8s`).
- When updating: Bump `LIBAPI` (breaking) or `LIBPATCH` (non-breaking) in the library file.
- The tox static check (commented out) validates version bumps on changed libraries.

## Common Patterns

### Adding a new receiver/exporter
1. Add configuration in `ConfigManager` method (e.g., `add_foo_forwarding(endpoint)`).
2. Use `self.config.add_component(Component.receiver, name, config, pipelines=[...])`.
3. Pipeline naming: Use `f"{signal_type}/{self.unit.name}"` (e.g., `metrics/otelcol-0`).
4. Update `integrations.py` if relation data is involved.

### Testing config changes
1. Add unit test in `tests/unit/test_config_manager.py` using Context.
2. Verify generated YAML structure with `yaml.safe_load(config_path.read_text())`.
3. For integration tests, grep snap logs for expected telemetry patterns (see `helpers.is_pattern_in_snap_logs()`).

### Debugging snap issues
- Check registration state: `ls /opt/singleton_snaps/LCK..*`
- View snap logs: `sudo snap logs opentelemetry-collector -n=all`
- Inspect fstab mounts: `cat /var/lib/snapd/mount/snap.opentelemetry-collector.fstab`
- Config files: `ls /etc/otelcol/config.d/` and check YAML syntax.

## Key Files Reference
- `src/charm.py`: Main charm logic, hook handlers, `_reconcile()` orchestration
- `src/config_manager.py`: High-level config API, tail sampling, pipeline management
- `src/integrations.py`: All relation handlers and charm library interactions
- `src/singleton_snap.py`: File-based locking for shared snap management
- `charmcraft.yaml`: Relation definitions, config options, platform targets
- `tests/unit/conftest.py`: Scenario Context fixtures, mocking patterns
- `tests/integration/conftest.py`: Jubilant model fixtures, charm building with log level tweaks

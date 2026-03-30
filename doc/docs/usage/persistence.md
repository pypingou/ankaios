# Workload Persistence

## Overview

By default, workloads added at runtime via CLI or API are ephemeral and lost when the Ankaios server restarts. The persistence feature allows you to mark workloads as persistent, ensuring they survive server restarts.

## Marking Workloads as Persistent

### Using YAML Manifests

Add `persist: true` to workload definitions:

```yaml
apiVersion: v0.1
workloads:
  nginx:
    runtime: podman
    agent: agent_A
    runtimeConfig: "nginx:latest"
    persist: true  # This workload survives restart

  debug-shell:
    runtime: podman
    agent: agent_A
    runtimeConfig: "busybox:latest"
    persist: false  # Temporary (this is the default)
```

### Using the CLI

Use the `--persist` flag with `ank run workload`:

```bash
# Persistent workload
ank run workload nginx \
  --runtime podman \
  --agent agent_A \
  --config "nginx:latest" \
  --persist

# Temporary workload (default - no --persist flag)
ank run workload debug \
  --runtime podman \
  --agent agent_A \
  --config "busybox:latest"
```

### Using ank apply

```bash
# Apply a manifest with persistent workloads
ank apply infrastructure.yaml
```

## Server Configuration

Enable persistence by configuring the runtime state file location in `/etc/ankaios/ank-server.conf`:

```toml
version = "v1"
startup_manifest = "/etc/ankaios/startup.yaml"
state_persistence_file = "/var/lib/ankaios/runtime_state.yaml"
address = "127.0.0.1:25551"
```

## How It Works

### Startup Process

1. **Load Startup Manifest** - Server loads base configuration from startup_manifest file
2. **Load Runtime State** - Server loads persistent workloads from state_persistence_file
3. **Merge States** - Runtime state overrides startup manifest (runtime wins on conflicts)
4. **Start Server** - Server starts with merged state

### Runtime Behavior

When you update state (add/modify/delete workloads):

1. **Update succeeds** - State is updated in memory
2. **Filter persistent workloads** - Only workloads with `persist: true` are selected
3. **Save to file** - Persistent workloads are written to runtime_state.yaml
4. **Atomic write** - File is written atomically with backup creation

### Restart Behavior

When the server restarts:

- **Persistent workloads** are automatically restored
- **Temporary workloads** are lost (as intended)
- **Startup manifest** remains unchanged

## Use Cases

### Infrastructure Workloads (Persistent)

Mark these as `persist: true`:

- System monitoring agents
- Database containers
- Message queue services
- Core platform services
- Long-running applications

### Ephemeral Workloads (Temporary)

Leave these as `persist: false` (default):

- Debug containers
- Test workloads
- Development tools
- One-time diagnostic tasks
- Temporary troubleshooting containers

## File Locations

| File | Purpose | Modified By |
|------|---------|-------------|
| `/etc/ankaios/startup.yaml` | Base configuration | User (manual) |
| `/var/lib/ankaios/runtime_state.yaml` | Persistent workloads | Ankaios (automatic) |
| `/var/lib/ankaios/runtime_state.backup` | Safety backup | Ankaios (automatic) |

## Resetting Runtime State

To clear all runtime changes and revert to the startup manifest:

```bash
# Stop the server
sudo systemctl stop ank-server

# Remove runtime state
sudo rm /var/lib/ankaios/runtime_state.yaml

# Start the server
sudo systemctl start ank-server
```

Now only workloads from the startup manifest will be running.

## Examples

### Example 1: Infrastructure Setup

**Startup manifest** (`/etc/ankaios/startup.yaml`):

```yaml
apiVersion: v0.1
workloads:
  prometheus:
    runtime: podman
    agent: monitoring_node
    runtimeConfig: "prom/prometheus:latest"
    persist: true

  grafana:
    runtime: podman
    agent: monitoring_node
    runtimeConfig: "grafana/grafana:latest"
    persist: true
```

These monitoring workloads will always restart with the server.

### Example 2: Adding Temporary Debug Container

```bash
# Add a debug container (not persistent)
ank run workload debug-tools \
  --runtime podman \
  --agent app_node \
  --config "nicolaka/netshoot:latest"

# After server restart, debug-tools is gone
# but prometheus and grafana are still running
```

### Example 3: Adding Persistent Service at Runtime

```bash
# Add a new service that should persist
ank run workload redis \
  --runtime podman \
  --agent cache_node \
  --config "redis:alpine" \
  --persist

# This survives server restarts
```

### Example 4: Mixed Workloads

```yaml
apiVersion: v0.1
workloads:
  # Production database - persistent
  postgres:
    runtime: podman
    agent: db_node
    runtimeConfig: "postgres:15-alpine"
    persist: true

  # Application server - persistent
  app_server:
    runtime: podman
    agent: app_node
    runtimeConfig: "myapp:v1.2.3"
    persist: true

  # Test container - temporary
  integration_test:
    runtime: podman
    agent: test_node
    runtimeConfig: "myapp-test:latest"
    persist: false
```

## Checking Persistence Status

Currently, you can check which workloads are persistent by examining the state:

```bash
# Get all workloads with full details
ank get state desiredState.workloads

# Look for "persist: true" in the output
```

## Troubleshooting

### Workload Not Persisting

**Problem:** Workload disappears after server restart

**Solutions:**

1. Check that `persist: true` is set in the workload definition
2. Verify `state_persistence_file` is configured in server config
3. Check file permissions on `/var/lib/ankaios/` directory
4. Check server logs for persistence errors

### Persistence File Corruption

**Problem:** Server fails to load runtime state

**Solution:**

```bash
# Check the backup file
sudo cat /var/lib/ankaios/runtime_state.backup

# If backup is good, restore it
sudo cp /var/lib/ankaios/runtime_state.backup \
       /var/lib/ankaios/runtime_state.yaml

# Restart server
sudo systemctl restart ank-server
```

### Old Workloads Persisting

**Problem:** Deleted workloads reappear after restart

**Solution:**
The workload might be in both startup manifest and runtime state. Check both files and remove from the appropriate location.

## Best Practices

1. **Use startup manifest for base infrastructure** - Core services that should always run
2. **Use persist flag for runtime additions** - Services added after deployment that should survive restarts
3. **Don't persist debug containers** - Keep troubleshooting tools ephemeral
4. **Document persistent workloads** - Maintain documentation of what's in runtime state
5. **Backup regularly** - Keep backups of both startup manifest and runtime state
6. **Test recovery** - Periodically test server restart to ensure persistence works

## Limitations

- **No per-config persistence** - All configs are persisted (cannot mark individual configs as temporary)
- **No automatic cleanup** - Old persistent workloads remain until explicitly deleted
- **No persistence history** - Only current state is saved, no versioning
- **Single persistence file** - All persistent workloads go to one file

## See Also

- [Complete State](../reference/complete-state.md)
- [Configuration Files](../reference/config-files.md)
- [Startup Configuration](../reference/startup-configuration.md)

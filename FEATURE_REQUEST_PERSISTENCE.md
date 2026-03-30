# Feature Request: Per-Workload State Persistence

## Problem

Currently, workloads added at runtime via CLI/API are lost when the Ankaios server restarts. All state changes are ephemeral and only the startup manifest survives. This creates issues for production deployments where:

- Infrastructure workloads (monitoring, databases) should persist across restarts
- Temporary/debug workloads should remain ephemeral
- Manual state reconstruction after restarts is error-prone

## Proposed Solution

Add a `persist` field to the `Workload` message allowing per-workload persistence control:

```yaml
apiVersion: v0.1
workloads:
  nginx:
    runtime: podman
    agent: agent_A
    runtimeConfig: "nginx:latest"
    persist: true  # Survives restart

  debug-shell:
    runtime: podman
    agent: agent_A
    runtimeConfig: "busybox:latest"
    # No persist field = temporary (default: false)
```

## Architecture

```
/etc/ankaios/startup.yaml          # Base config (never modified)
/var/lib/ankaios/runtime_state.yaml  # Auto-managed persistent workloads
```

**Startup flow:**
1. Load startup manifest (base configuration)
2. Load runtime state file (persistent workloads)
3. Merge (runtime overrides startup)

**Runtime flow:**
- On state updates: filter workloads with `persist: true` → save to runtime_state.yaml
- Atomic writes with backup for safety
- Best-effort (errors logged, don't fail updates)

## Use Cases

**Persistent (infrastructure):**
- System monitoring containers
- Database containers
- Long-running services

**Temporary (ephemeral):**
- Debug/troubleshooting containers
- Test workloads
- Development tools

## API Changes

### Protobuf
```protobuf
message Workload {
    // ... existing fields ...
    Files files = 9;
    optional bool persist = 10;  // NEW
}
```

### CLI
```bash
# Persistent workload
ank run workload nginx --runtime podman --agent agent_A \
  --config "nginx:latest" --persist

# Temporary (default)
ank run workload debug --runtime podman --agent agent_A \
  --config "busybox:latest"
```

### Server Config
```toml
version = "v1"
startup_manifest = "/etc/ankaios/startup.yaml"
state_persistence_file = "/var/lib/ankaios/runtime_state.yaml"  # NEW
```

## Implementation Scope

- **Protobuf**: Add `persist` field to Workload message
- **Server**: Filter/persist workloads after UpdateStateRequest, load at startup
- **CLI**: Add `--persist` flag to run command
- **Configs**: All configs are persisted (no per-config control)
- **Safety**: Atomic writes, backups, graceful error handling

**Estimated changes:** ~10 files, ~435 LOC, ~20 tests

## Alternatives Considered

1. **Tag-based** (`ankaios.io/persist: "true"`): Works but less clean than native field
2. **Per-request flag**: Requires users to remember `--persist` on every apply
3. **Always persist everything**: No control over ephemeral workloads

## Backwards Compatibility

✅ Fully backwards compatible
✅ `persist` field is optional (default: false)
✅ Existing manifests/CLI commands work unchanged
✅ New feature is opt-in

## Questions for Maintainers

1. Does this align with Ankaios design philosophy?
2. Preferred persistence file location/format?
3. Should configs have per-config persistence control?
4. Any concerns with the protobuf change?

---

**Would you like me to implement this feature and submit a PR?**

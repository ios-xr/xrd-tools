# Native Compute

Native compute is the zero-dependency compute mode. The user manages their own
Docker hosts — no compute skill or automation is involved.

Use native compute when:

- No compute skill is available in the workspace
- You want to use your own Docker infrastructure directly
- You explicitly prefer manual control over compute

## Required Variables

Set these before launching a lab:

```bash
export LAB_COMPUTE_BACKEND=native
export DOCKER_HOST="ssh://user@host:port"   # or leave unset for local Docker
export LAB_COMPUTE_SESSION="${DOCKER_HOST:-local}"
export XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1
```

| Variable | Description |
|----------|-------------|
| `LAB_COMPUTE_BACKEND` | Always `native` |
| `LAB_COMPUTE_SESSION` | Set to `${DOCKER_HOST:-local}` — identifies the compute session |
| `DOCKER_HOST` | Docker daemon connection. Unset = local Docker socket. |
| `XR_LAB_XRD_IMAGE` | XRd image path or registry reference |

`LAB_COMPUTE_SESSION` must match `DOCKER_HOST` (or be `local` when `DOCKER_HOST`
is unset). This is what the session-conflict guard and `in-use-sessions` use to
track which labs are running where.

## Optional Variables

| Variable | Description |
|----------|-------------|
| `LAB_COMPUTE_CPUS` | CPUs available (set if known — enables resource awareness) |
| `LAB_COMPUTE_RAM` | RAM in GB (set if known — enables resource awareness) |
| `XR_COMPOSE_CMD` | Override xr-compose command (default: `xr-compose`) |

If `LAB_COMPUTE_CPUS` and `LAB_COMPUTE_RAM` are not set, the resource-awareness
check is skipped. See [running-labs.md](running-labs.md) for details.

## Examples

### Local Docker

```bash
export LAB_COMPUTE_BACKEND=native
export LAB_COMPUTE_SESSION=local
export XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1
# DOCKER_HOST left unset — uses local Docker socket
```

### Single remote host

```bash
export LAB_COMPUTE_BACKEND=native
export DOCKER_HOST="ssh://root@my-server:22"
export LAB_COMPUTE_SESSION="${DOCKER_HOST}"
export XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1
```

### Multiple remote hosts (concurrent labs)

```bash
# Session 1
export LAB_COMPUTE_BACKEND=native
export DOCKER_HOST="ssh://root@server-a:22"
export LAB_COMPUTE_SESSION="${DOCKER_HOST}"
export XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1
# launch lab A ...

# Session 2 — switch DOCKER_HOST and SESSION
export DOCKER_HOST="ssh://root@server-b:22"
export LAB_COMPUTE_SESSION="${DOCKER_HOST}"
# launch lab B ...
```

Each distinct `DOCKER_HOST` value is a separate session. The session-conflict
guard prevents launching two labs on the same host.

## Differences from managed compute

| Capability | Managed (e.g., dvm-compute) | Native |
|---|---|---|
| Session discovery | Automatic | User specifies `DOCKER_HOST` |
| Resource discovery | Automatic (`LAB_COMPUTE_CPUS`/`RAM`) | Manual or unavailable |
| Session allocation | Scripted (`setup-env.sh`) | Manual `export` commands |
| Session tracking | `.dvm-compute/current` | Not tracked between shell sessions |
| Image resolution | Automatic (workspace or registry) | User sets `XR_LAB_XRD_IMAGE` |

Running-lab state tracking (`.xr-compose-tool/running/*.env`) works identically
for both modes.

# XR Compose Tooling Reference

## Wrapper

**NEVER run `docker` or `docker-compose` commands directly.** All lab interactions—including status checks (`ps`), logs, and exec—must use the wrapper script.

- Wrapper: `<skills>/xr-compose-tool/scripts/just-wrapper.sh`
- Invocation: `./<skills>/xr-compose-tool/scripts/just-wrapper.sh <task> [args]`

## Available Tasks

```
clean                    # Clean up all stopped containers and networks
exec router              # Run an EXEC shell on a router (usage: just exec <router>)
in-use-sessions          # List compute sessions in use by running labs (one per line)
launch lab               # Launch a lab (usage: just launch <lab-path>)
list-labs                # List all available labs (searches for docker-compose.xr.yml)
list-routers             # List all routers in the current lab (returns space-separated list)
log router               # Follow logs for a specific router
logs lab                 # Follow logs for the entire lab
ps                       # Show running containers
restart lab              # Restart a lab (shutdown then launch)
run router command       # Run a command on a router (usage: just run <router> <command>)
running                  # Show which labs are currently running
shutdown lab             # Shutdown a lab (usage: just shutdown <lab-path>)
wait-for-boot routers="" # Wait for routers to boot (usage: just wait-for-boot "r1 r2")
```

## Environment Variables

### Image Configuration

- `XR_LAB_XRD_IMAGE` - XRd image path or registry reference
  - Can be an archive path (e.g., `/path/to/xrd.tgz`) or registry reference (e.g., `ios-xr/xrd-control-plane:7.11.1`)
  - Passed via `-i` to xr-compose (works for both types)
  - Default: `ios-xr/xrd-control-plane:latest`

### Optional

- `XR_LAB_ROOT` - Override root directory for lab discovery and relative paths
  - Default: current working directory
  - Typically not needed. Useful for listing/working with labs outside the workspace.
  - Lab paths in `launch`/`shutdown` can be relative (to root) or absolute.

- `XR_COMPOSE_CMD` - xr-compose command to use
  - Default: `xr-compose`

- `DOCKER_HOST` - Docker daemon connection
  - Default: local Docker socket (unset)

- `XR_LAB_XRD_VERSION` - XRd version tag (used when building default image name)
  - Default: `latest`

## Compute Infrastructure

A compute mode must be active before launching labs. This sets `DOCKER_HOST`,
`XR_LAB_XRD_IMAGE`, and the `LAB_COMPUTE_*` variables that session management
depends on.

Two options:

- **Managed compute** — use a compute skill (e.g., dvm-compute) which handles
  setup automatically via its `setup-env.sh` script
- **Native compute** — set the variables manually; see
  [native-compute.md](native-compute.md)

See [running-labs.md](running-labs.md) for state management, session handling,
and resource-awareness guidance.

### Example: Managed compute

```bash
# Configure environment via compute skill (sets all required variables)
source <skills>/dvm-compute/scripts/setup-env.sh

# Then launch
./<skills>/xr-compose-tool/scripts/just-wrapper.sh launch my-lab
```

### Example: Native compute

```bash
# Set variables manually
export LAB_COMPUTE_BACKEND=native
export DOCKER_HOST="ssh://root@my-server:22"
export LAB_COMPUTE_SESSION="${DOCKER_HOST}"
export XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1

# Then launch
./<skills>/xr-compose-tool/scripts/just-wrapper.sh launch my-lab
```

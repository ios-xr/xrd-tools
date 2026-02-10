# Running-Lab State and Compute Management

## Running-Lab State

Running labs are tracked in `.xr-compose-tool/running/` at the workspace root.
Each running lab has a `.env` file named after the sanitized lab path (e.g.,
`srv6_l3vpn.env`).

### .env file format

Every `.env` file contains operational variables and compute identity. The
compute variables (`LAB_COMPUTE_*`) are always present — set by whichever
compute mode is active (managed or native).

**Managed compute example** (e.g., dvm-compute):

```bash
LAB_PATH=srv6_l3vpn
DOCKER_HOST=ssh://root@localhost:48011
XR_COMPOSE_CMD=xr-compose-dev
XR_LAB_XRD_IMAGE=containers.cisco.com/xrd-prod/xrd-control-plane:latest
LAB_COMPUTE_BACKEND=dvm-compute
LAB_COMPUTE_SESSION=48011
LAB_COMPUTE_CPUS=12
LAB_COMPUTE_RAM=32
```

**Native compute example**:

```bash
LAB_PATH=srv6_l3vpn
DOCKER_HOST=ssh://root@my-server:22
XR_COMPOSE_CMD=xr-compose
XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1
LAB_COMPUTE_BACKEND=native
LAB_COMPUTE_SESSION=ssh://root@my-server:22
```

### Lifecycle

- `launch` writes the tracking file **before** starting containers; on failure
  it cleans up the file so no ghost entries remain
- `shutdown` always removes the tracking file, even if `docker-compose down`
  errors
- `running` lists all tracked labs
- Multiple labs can run simultaneously (each has its own `.env` file)

## Compute Identity

All compute modes — managed (e.g., dvm-compute) and native — export variables
prefixed with `LAB_COMPUTE_`:

| Variable | Purpose | Always present? |
|----------|---------|-----------------|
| `LAB_COMPUTE_BACKEND` | Identifies the compute mode (e.g., `dvm-compute`, `native`) | Yes |
| `LAB_COMPUTE_SESSION` | Session identifier (unique per compute session) | Yes |
| `LAB_COMPUTE_CPUS` | CPUs available on the compute session | Only with managed compute |
| `LAB_COMPUTE_RAM` | RAM (GB) available on the compute session | Only with managed compute |

When a lab is launched, the Justfile captures all `LAB_COMPUTE_*` variables
from the environment and stores them in the `.env` file.

## Session Management

Each running lab requires its own compute session. `launch` will refuse to
start if the current `LAB_COMPUTE_SESSION` is already in use by another lab.
Allocate separate compute (or switch `DOCKER_HOST` for native compute) before
launching additional labs.

- `in-use-sessions` lists the `LAB_COMPUTE_SESSION` values from all running
  labs. Use this to tell the compute skill which sessions to exclude when
  allocating new compute (e.g., via `LAB_COMPUTE_EXCLUDE_SESSIONS`).

## Resource Awareness

Before launching a lab — especially when switching to a different lab or after
modifying a topology — check that the compute session has enough resources.

### When to check

- Launching a lab for the first time on a compute session
- Switching to a different lab on the same compute session
- After adding routers to an existing lab's `docker-compose.xr.yml`
- Re-launching a lab that previously failed due to resource issues

### How to check

1. Count the XR routers in the lab's `docker-compose.xr.yml` (services without
   `non_xr: true`)
2. Compute required resources:
   - **CPUs** = 2 + router count
   - **RAM (GB)** = 2 + 3 x router count
3. Compare against `LAB_COMPUTE_CPUS` and `LAB_COMPUTE_RAM`

### If compute is insufficient

Warn the user that the current compute session does not have enough resources
and suggest re-allocating compute with a larger profile before launching.

Do **not** silently proceed — under-provisioned launches typically fail at the
container level and waste time.

### If capacity variables are absent

If `LAB_COMPUTE_CPUS` / `LAB_COMPUTE_RAM` are not set (e.g., native compute),
resource awareness is unavailable. Skip the check — the user is responsible for
ensuring their Docker host has sufficient capacity.

# XRd Lab Skills

These skills give an AI agent the expertise to design, launch and interact
with XRd virtual labs using xr-compose. They follow the open
[Agent Skills](https://agentskills.io) standard and work with any compatible
agent.


## Included Skills

### xr-lab-assistant

The main skill. Covers the full lab lifecycle:

- **Designing** -- create and update lab topologies (`docker-compose.xr.yml`)
  and per-router IOS-XR configurations
- **Launching** -- start, stop and test labs, with structured post-launch
  validation
- **Interacting** -- run show commands, troubleshoot, and verify against
  running routers

### xr-compose-tool

The tooling layer used by xr-lab-assistant as its lab backend. Wraps
xr-compose and docker-compose behind a managed workflow with session tracking
and resource awareness. Both skills should be installed together.


## Installation

Consult your agent's documentation for the directory where skills are
discovered. Both `xr-lab-assistant` and `xr-compose-tool` should be installed.

For example, with GitHub Copilot you can copy or symlink the skill directories
into `.github/skills/` in your workspace:

```bash
cp -r skills/xr-lab-assistant .github/skills/
cp -r skills/xr-compose-tool  .github/skills/
```


## Compute Setup

Before launching labs the agent needs a Docker environment and an XRd image.
Set the following environment variables in your shell:

```bash
export LAB_COMPUTE_BACKEND=native
export DOCKER_HOST="ssh://user@host:port"   # or leave unset for local Docker
export LAB_COMPUTE_SESSION="${DOCKER_HOST:-local}"
export XR_LAB_XRD_IMAGE=ios-xr/xrd-control-plane:7.11.1
```

| Variable | Description |
|----------|-------------|
| `DOCKER_HOST` | Docker daemon connection. Leave unset to use the local Docker socket. |
| `XR_LAB_XRD_IMAGE` | XRd image path (`.tgz`) or registry reference. |
| `LAB_COMPUTE_BACKEND` | Set to `native`. |
| `LAB_COMPUTE_SESSION` | Set to `${DOCKER_HOST:-local}` -- identifies the compute session. |

Multiple `DOCKER_HOST` values can be used to run concurrent labs on different
hosts -- each distinct value is treated as a separate session, and the tooling
prevents two labs from being launched on the same host.

> **Note:** Additional compute automation skills can be provided separately to
> handle environment discovery and session management automatically.

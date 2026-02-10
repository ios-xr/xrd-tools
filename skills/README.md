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

For example, with GitHub Copilot you can symlink the skill directories into
`.github/skills/` in your workspace:

```bash
ln -s /path/to/xrd-tools/skills/xr-lab-assistant .github/skills/
ln -s /path/to/xrd-tools/skills/xr-compose-tool  .github/skills/
```


## Compute Setup

The skills use the Docker environment available in the shell:

- **Docker host** -- the current `DOCKER_HOST` value is used, or the local
  Docker socket if unset. You can also ask the agent to switch between
  different `DOCKER_HOST` values during a session to run concurrent labs on
  separate hosts.
- **XRd image** -- defaults to `ios-xr/xrd-control-plane:latest`. XRd images
  are not available on Docker Hub; the image must already be loaded into the
  local Docker image store (e.g. via `docker load`). To use a different image
  or version, tell the agent in the conversation.

> **Note:** Additional compute automation skills can be provided separately to
> handle environment discovery and session management automatically.

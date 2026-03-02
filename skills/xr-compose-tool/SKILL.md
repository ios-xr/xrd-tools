---
name: xr-compose-tool
description: Launching, stopping, or managing xr-compose-based XRd labs, running commands/logs via the just wrapper, or working with docker-compose.xr.yml topology files.
---

# XR Compose Tool

## Overview

Provide the xr-compose tooling layer for XRd labs in this repo.

## Related Skills

This skill may depend on compute infrastructure skills for Docker environment setup.

### Compute Infrastructure

A compute mode must be active before launching labs. It configures the Docker
environment (`DOCKER_HOST`, image paths) and sets the `LAB_COMPUTE_*` variables
that session management depends on.

**Selection:**
- If one compute skill is available, use it — read its SKILL.md and follow setup.
- If multiple compute skills are available, ask the user which to use (once per session).
- If no compute skills are available, use native compute (see
  [references/native-compute.md](references/native-compute.md)).
- If the user explicitly requests native compute, use it regardless of available
  compute skills.
- Remember the selection for the session duration.

## Tooling

Use the wrapper script and task list in [references/tooling.md](references/tooling.md) for all lab interactions. Direct docker or docker-compose invocations bypass session tracking and break lab state management.

## Running Labs and Compute

Running-lab state tracking, compute session management, and resource-awareness
guidance are in [references/running-labs.md](references/running-labs.md).

## Compose File Format

Follow the topology file guidance and template in [references/compose-file.md](references/compose-file.md).

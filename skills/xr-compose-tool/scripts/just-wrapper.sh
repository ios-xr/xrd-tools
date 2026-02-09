#!/usr/bin/env bash
# XR Compose Tool - Just Wrapper
#
# Invokes the Justfile with appropriate defaults.
# Environment can be pre-configured by a compute skill.
#
# Environment Variables (optional, have sensible defaults):
#   DOCKER_HOST      - Docker daemon connection (default: local socket)
#   XR_COMPOSE_CMD   - xr-compose command to use (default: xr-compose)
#   XR_LAB_XRD_IMAGE - XRd image path or registry reference
#   XR_LAB_ROOT      - Override root directory (default: current directory)
#                      Typically not needed. Useful for listing/working with
#                      labs outside the current workspace.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
JUSTFILE="${SKILL_DIR}/assets/Justfile"

# Apply defaults for optional environment variables
export XR_COMPOSE_CMD="${XR_COMPOSE_CMD:-xr-compose}"
export XR_LAB_XRD_VERSION="${XR_LAB_XRD_VERSION:-latest}"
export XR_LAB_XRD_IMAGE="${XR_LAB_XRD_IMAGE:-ios-xr/xrd-control-plane:${XR_LAB_XRD_VERSION}}"
# DOCKER_HOST: no default (uses local Docker socket if unset)

exec just --justfile "${JUSTFILE}" -d "${XR_LAB_ROOT:-$(pwd)}" "$@"

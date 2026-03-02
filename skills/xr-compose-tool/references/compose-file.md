# XR Compose Topology File

## File Name

Use `docker-compose.xr.yml` for xr-compose labs.

## Format

Describes routers and connectivity. Follow the template in `references/xr-compose-template.xr.yml`.

**Router naming**: Service names must be at least 2 characters (e.g., use `p1` instead of `p`).

## Image Specification

How to handle the `image` field depends on the image source:

### Archive Images (`.tgz` files)

When using a tarball image (e.g., workspace-built image):
- **Omit** the `image` field in the topology file—specifying it would conflict with the `-i` argument and cause xr-compose to look for an image that isn't in the topology
- Pass the image via `-i <path>` argument to xr-compose
- xr-compose handles loading and tagging the image

### Registry Images

When using a Docker registry reference:
- The image is passed via `--image <reference>` to xr-compose
- xr-compose sets the image for all XRd services

**Note:** In most cases, omit `image` from the topology file.
The tooling passes the image via command-line arguments based on `XR_LAB_XRD_IMAGE`.

## Template Reference

See `references/xr-compose-template.xr.yml` for the full schema including:
- Service definitions with `xr_startup_cfg` and `xr_interfaces`
- L2 network connections via `xr_l2networks`
- Non-XR services with `non_xr: true`

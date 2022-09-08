# Changelog


## Preview 7.8.1

Changes added to the preview for 7.8.1.

- Add `--boot-log-level` arg in `launch-xrd` (supported in XR 7.8.1 onwards)
- Stop passing host `/sys/fs/cgroup` mount through to the container
- Update cgroup check in `host-check` and remove corresponding "Systemd mounts" check (no longer required for XR 7.8.1 onwards)
- Remove hard requirement for cgroups v1 in `host-check` (cgroups v2 supported for lab use)


## v1 (active)

The v1 release supports Cisco IOS-XR release version 7.7.1.
It is planned to support 7.8.1 when this version is released.


### v1.0.1 (2022-09-07)

- Emit a warning in `host-check` when 2M hugepages are used, as this is not a
supported deployment use case.


### v1.0.0 (2022-07-15)

First release.

- Scripts: `host-check`, `launch-xrd`, `xr-compose`, `apply-bugfixes`
- Templates: MacVLAN launch-xrd example, xr-compose template
- Sample xr-compose topologies: 'simple-bgp', 'bgp-ospf-triangle, 'segment-routing'
- Tests: host-check UT

# Changelog


## v1 (active)

The v1 release supports Cisco IOS-XR release versions 7.7.1 and 7.8.1.

## v1.1.0 (2022-12-02)

Changes corresponding to the release of XR version 7.8.1.

- Add `--boot-log-level` arg in `launch-xrd` (supported in XR 7.8.1 onwards)
- Stop passing host `/sys/fs/cgroup` mount through to the container
- Update cgroup check in `host-check` and remove corresponding "Systemd mounts" check (no longer required for XR 7.8.1 onwards)
- Remove hard requirement for cgroups v1 in `host-check` (cgroups v2 supported for lab use)

### v1.0.5 (2022-12-02)

- In the `launch-xrd` script the mechanism for passing extra args to the container manager has changed. The `--args` argument is no longer required - every unrecognised argument will be passed to the container manager. The container image must now be passed as the last argument to the script. The `--args` method is still supported for backwards compatibility, but will be removed in the future.

### v1.0.4 (2022-11-30)

- Indicate when a command times out in the `host-check` script.

### v1.0.3 (2022-10-26)

- To check if AppArmor is enabled, `host-check` script now looks at `"/sys/kernel/security/apparmor/profiles"` instead of `"/sys/module/apparmor/parameters/enabled"`.
- `host-check` now gives a warning if AppArmor is enabled.


### v1.0.2 (2022-09-21)

- Do not run 'extra checks' in `host-check` by default.
- Make igb_uio a supported PCI driver, only failing `host-check` if no interface driver is loaded.
- Only check if IOMMU is enabled if vfio-pci is being used, and handle the case where the vfio-pci 'no IOMMU' mode is unconfigurable.


### v1.0.1 (2022-09-07)

- Emit a warning in `host-check` when 2M hugepages are used, as this is not a
supported deployment use case.


### v1.0.0 (2022-07-15)

First release.

- Scripts: `host-check`, `launch-xrd`, `xr-compose`, `apply-bugfixes`
- Templates: MacVLAN launch-xrd example, xr-compose template
- Sample xr-compose topologies: 'simple-bgp', 'bgp-ospf-triangle, 'segment-routing'
- Tests: host-check UT

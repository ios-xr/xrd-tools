# Changelog


## v1 (active)

The v1 release supports Cisco IOS-XR release version 7.7.1.
It is planned to support 7.8.1 when this version is released.


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

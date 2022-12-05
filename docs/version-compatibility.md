# Version Compatibility

This file documents compatibility between versions of this project with XR releases.
In some cases extra arguments will be required to continue using older XR releases, and those cases will be documented here.


## v1.1

Supports XR 7.7.1 and 7.8.1 (the first and most recent released versions of XRd).

### XR 7.7.1

- Does not support the `--boot-log-level` arg in `launch-xrd`.
- Requires the host cgroup mount to be passed into the container manually:
  - Use '`--args '-v /sys/fs/cgroup:/sys/fs/cgroup:ro'`' to `launch-xrd`.
  - Add the following under the 'service' section in an `xr-compose` topology:
    ```yaml
    volumes:
    - source: /sys/fs/cgroup
      target: /sys/fs/cgroup
      type: bind
      read_only: True
    ```
- Does not support running with `--cgroupns=private`.
- Requires `/sys/fs/cgroup/systemd/` to be mounted read-write on the host.
- Does not support cgroups v2.


## v1.0

Supports XR 7.7.1 (the first released version of XRd).

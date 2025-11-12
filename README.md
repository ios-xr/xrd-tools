[![Check release](https://github.com/ios-xr/xrd-tools/actions/workflows/check-release.yml/badge.svg)](https://github.com/ios-xr/xrd-tools/actions/workflows/check-release.yml)

# XRd Tools

This repository contains tools for working with XRd containers.

Accompanying documentation is coming soon.

See [CHANGELOG.md](CHANGELOG.md) for a record of changes that have been made.

See [docs/version-compatibility.md](docs/version-compatibility.md) for the compatibility statement across versions.


## Download

Download an archive from the [releases page](https://github.com/ios-xr/xrd-tools/releases).


## System Dependencies

XRd is only able to run on Linux, therefore the scripts provided here are also targeting Linux.

The scripts are implemented in bash and python3, which must therefore be found on `PATH`.
All active versions of python3 are supported.

The following scripts have additional dependencies on top of the above:
- `xr-compose`: also requires `docker-compose` (v1) to be on `PATH` and for the `PyYAML` python package be installed (e.g. in an active virtual environment).
- `apply-bugfixes`: also requires `docker build`

Further note that for AppArmor enabled systems you **must** have the
`xrd-unconfined` profile installed and enabled, and pass the appropriate
command line options to `launch-xrd` / `xr-compose`/ `docker` / `podman` to use it.
See [AppArmor](#apparmor) for more information.

## Repo Contents

Accompanying documentation is coming soon.

### `profiles/`

Contains the AppArmor profile `xrd-unconfined` required to run XRd on Ubuntu
systems with AppArmor enabled. See [AppArmor](#apparmor) for more details.

### `scripts/`

Check the usage of the scripts by passing `--help`.

* `apply-bugfixes` - Create a new XRd image with bugfixes installed on top of a base image (see [Apply Bugfixes](#apply-bugfixes) for more details)
* `host-check` - Check the host is set up correctly for running XRd containers.
* `launch-xrd` - Launch a single XRd container, or use `--dry-run` to see the args required.
* `xr-compose` - Launch a topology of XRd containers (wraps `docker-compose`).

### `samples/`

Sample files, e.g. `xr-compose` topology samples.

### `templates/`

Template files, whether illustrative scripts or template config/topology files.

### `tests/`

Tests for the scripts.

### `Dockerfile.host-check`

Dockerfile for producing a `host-check` container image.


## Versioning Scheme

This project loosely follows semantic versioning.
Version numbers consist of major, minor and patch, e.g. `v1.0.2`.

Cosmetic changes will involve a patch bump, moderate (possibly breaking) changes will be a minor bump, while significant backwards-incompatible changes require a major version bump.

Major version bumps are avoided as much as possible since we want to maintain backwards compatibility!
An example of a breaking change requiring a major version bump would be dropping support for an old XR release version, however this should not be a common occurrence (we aim to maintain compatibility of at least 3 release versions at a time).

Minor version bumps may introduce incompatibilities with previous invocations as long as these are documented in [version-compatibility.md](docs/version-compatibility.md), and as long as there's still a way to tweak the invocation to work with the same range of XR releases.

## Apply Bugfixes
XRd has a different workflow to other XR platforms for installing bugfixes.

Instead of applying bugfixes to a running instance via XR CLI, a container build is used to install bugfixes/new packages against an existing XRd image, creating a new container image with the bugfixes.

The user then stops any instances of XRd that are using the old image, and starts new instances using the new updated image.

The `apply-bugfixes` script (in this repo) provides a user friendly wrapper for doing the building of the new image.

And is used as follows:
```
Usage: apply-bugfixes [-h|--help] [--new-packages] IMAGE SOURCE ...

Create a new XRd image with bugfixes installed on top of a base image.

Required arguments:
  IMAGE            Loaded container image to install bugfixes on top of.
  SOURCE           Path to source to install packages from - a directory
                   or tarball containing the rpm(s) to install.

Optional arguments:
  --new-packages   Install new packages if included in the bugfix source. By
                   default, only packages that are already installed in the
                   base image will be updated, so this should be passed if
                   any new packages are present in SOURCE.
  ...              Additional args passed through to 'docker build' (such as
                   --tag).
```

Example workflow to install a bugfix:
- Load XRd image into image repo (e.g. `ios-xr/xrd-vrouter:25.1.1`).
- Run apply-bugfixes, passing the image repo name/tag, pointer to the bugfix tarball/dir, optionally specify a tag for the newly created image:
  - `apply-bugfixes ios-xr/xrd-vrouter:25.1.1 /path/to/bugfixes.tar.gz --tag bugfixes`
- Stop any XRd instances using the old image.
- Launch new instances of XRd using the updated image, with previous set of launch arguments and volumes.

## AppArmor

XRd is able to run on AppArmor-enabled Ubuntu environments only if the `xrd-unconfined` AppArmor profile is installed and enabled. 
Passing the `--apparmor-enabled` argument to `launch-xrd` and `xr-compose` will use this profile, and therefore explicitly requires it to be installed prior to launching the container. 

To install and enable the profile, follow these steps:
- Copy the profile to the correct location on the host using `cp xrd-tools/profiles/xrd-unconfined
  /etc/apparmor.d/xrd-unconfined`
- Activate the AppArmor profile on the host by running `apparmor_parser -r
  /etc/apparmor.d/xrd-unconfined`

If the container does not use this profile on AppArmor-enabled hosts, it will
either fail to launch or launch with boot errors. To ensure that the profile is
used, do the following:
- If using `launch-xrd` or `xr-compose`, add the `--apparmor-enabled` command
  line option.
    - Make sure the profile is installed and enabled prior to this step, it
      will automatically be used if so.
- If running `docker` or `podman` manually, ensure that the `--security-opt
  apparmor=xrd-unconfined` is passed as a command line option.
    - Make sure the profile is installed and enabled prior to this step.

**Note: See [TroubleShooting Common Errors](#troubleshooting-common-errors)
for potential errors that can be hit if this has not been set up correctly.**



### Known Limitations
Running XRd in privileged mode on AppArmor-enabled hosts under `docker` is not
supported. Note that this assumes that XRd is correctly trying to run with the `xrd-unconfined` profile.
The container may launch successfully upon first boot, but it is not guaranteed that the `xrd-unconfined` profile will be maintained upon `restart` or `stop` / `start`. For more information, please see 
the issue raised [here](https://github.com/moby/moby/issues/51242).

**Note that `podman` does not have this limitation**.

## Contributing

Thanks for considering contributing to the project!

Check out the repo's [open issues](https://github.com/ios-xr/xrd-tools/issues) or see [CONTRIBUTING.md](CONTRIBUTING.md) for more contributing guidelines.

## Troubleshooting Common Errors

Q: **I ran `launch-xrd` and I get the below error, what is the issue?**
```
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: unable to apply apparmor profile: apparmor failed to apply profile: write /proc/thread-self/attr/apparmor/exec: no such file or directory: unknown.
```

A: This means you do not have the `xrd-unconfined` AppArmor profile installed,
but have passed the `--apparmor-enabled` option to `launch-xrd`.
See the [AppArmor](#apparmor) section for information on how to install and
load the profile.

Q: **I ran `launch-xrd` specifically with `podman` and I get the below error,
what is the issue?**
```
Error: preparing container xxxxx for attach: AppArmor profile "xrd-unconfined" specified but not loaded
```

A: This means you do not have the `xrd-unconfined` AppArmor profile installed,
but have passed the `--apparmor-enabled` option to `launch-xrd`.
See the [AppArmor](#apparmor) section for information on how to install and
load the profile.

Q. **I ran `xr-compose` to create a yml, passed it to `docker-compose` OR used
the `-l` option and I got the below error, what is the issue?**

```
Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: unable to apply apparmor profile: apparmor failed to apply profile: write /proc/thread-self/attr/apparmor/exec: no such file or directory: unknown
ERROR: Unexpected exception: Command '['docker-compose', '-f', 'docker-compose.yml', 'up', '-d']' returned non-zero exit status 1.
```

A: This means you do not have the `xrd-unconfined` AppArmor profile installed,
but have passed the `--apparmor-enabled` option to `xr-compose`.
See the [AppArmor](#apparmor) section for information on how to install and
load the profile.

Q. **I launched the XRd container and notice this in my boot logs, what is the
issue?**
```
         Starting System Logging Service...
[FAILED] Failed to start System Logging Service.
See 'systemctl status rsyslog.service' for details.
```
A. This means you have launched XRd on an AppArmor-enabled host without the
correct AppArmor profile **and/or** without the correct command line argument
passed to `launch-xrd` / `xr-compose` / `docker` / `podman`. See the
[AppArmor](#apparmor) section for information on how to install load the
profile, and how to ensure that it is being used to launch the container.

Q: I launched a container using the `xrd-unconfined` profile I downloaded a
while ago, but I keep seeing the following error in `/var/log/kern.log`:

```
apparmor mqueue disconnected TODO
```

A: Your `xrd-unconfined` profile is out of date. From v1.2.2 of these tools,
the `mqueue` capability was removed from the profile. The removal of `mqueue`
from the profile will not impose unwanted permissions on that process because
it is [fully allowed by
default](https://manpages.debian.org/testing/apparmor/apparmor.d.5.en.html).
There is a [bug](https://bugs.launchpad.net/apparmor/+bug/2102237) in Ubuntu
versions earlier than 25.04 which will cause the log to appear. The log itself
does not indicate a problem with `mqueue` and can be ignored, but if you prefer
to not see it anymore, please update your current `xrd-unconfined` profile with
the latest version from this repository.
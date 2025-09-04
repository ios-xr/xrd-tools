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

The `xr-compose` script also requires `docker-compose` (v1) to be on `PATH` and for the `PyYAML` python package be installed (e.g. in an active virtual environment).


## Repo Contents

Accompanying documentation is coming soon.

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
Instead of applying bugfixes to a running instance via XR CLI, a docker build is used to install bugfixes/new packages against an existing XRd image, creating a new docker image with the bugfixes.

The `apply-bugfixes` script (in this repo) provides a user friendly wrapper for doing this:
```
Usage: apply-bugfixes [-h|--help] [--new-packages] IMAGE SOURCE ...

Create a new XRd image with bugfixes installed on top of a base image.

Required arguments:
  IMAGE            Loaded container image to install bugfixes on top of
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
- Load XRd image into image repo (e.g. `ios-xr/xrd-vrouter:25.1.1`)
- Run apply-bugfixes, passing the image repo name/tag, pointer to the bugfix tarball/dir, optionally specify a tag for the newly created image:
  - `apply-bugfixes ios-xr/xrd-vrouter:25.1.1 /path/to/bugfixes.tar.gz --tag bugfixes`
- Now launch XRd using the newly created image 


## Contributing

Thanks for considering contributing to the project!

Check out the repo's [open issues](https://github.com/ios-xr/xrd-tools/issues) or see [CONTRIBUTING.md](CONTRIBUTING.md) for more contributing guidelines.

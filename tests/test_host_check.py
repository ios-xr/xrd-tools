# Copyright 2021-2023 Cisco Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
UT for the host-check script, using pytest.
"""

import contextlib
import shlex
import subprocess
import textwrap
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union
from unittest import mock

import pytest

from . import utils
from .utils import REPO_ROOT_DIR


HOST_CHECK_SCRIPT = REPO_ROOT_DIR / "scripts" / "host-check"
host_check = utils.import_path(HOST_CHECK_SCRIPT)
CheckState = host_check.CheckState
Check = host_check.Check

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

CHECKS_BY_GROUP = {
    "base": host_check.BASE_CHECKS,
    **host_check.PLATFORM_CHECKS_MAP,
    **host_check.EXTRA_CHECKS_MAP,
}


def _checks_to_str(checks: List[host_check.Check]) -> str:
    return ", ".join(check.name for check in checks)


BASE_CHECKS_STR = _checks_to_str(host_check.BASE_CHECKS)
CONTROL_PLANE_CHECKS_STR = _checks_to_str(host_check.CONTROL_PLANE_CHECKS)
VROUTER_CHECKS_STR = _checks_to_str(host_check.VROUTER_CHECKS)


def perform_check(
    capsys,
    group: str,
    name: str,
    *,
    cmds: Optional[Union[Tuple[str, Any], List[Tuple[str, Any]]]] = None,
    files: Optional[Union[Tuple[str, Any], List[Tuple[str, Any]]]] = None,
    deps: Optional[List[str]] = None,
    failed_deps: Optional[List[str]] = None,
) -> Tuple[CheckState, str]:
    """
    Perform a single host check and return whether it succeeded and the output.

    :param group:
        The name of the group the check belongs to.
    :param name:
        The name of the check to perform.
    :param cmds:
        The subprocess command(s) that are expected to be run. Either a list
        or a single command, where each command is a tuple containing the
        command in string form and the mocked side effect of the command
        (stdout or exception).
    :param files:
        The file(s) that are expected to be read. Either a list
        or a single entry, where each entry is a tuple containing the
        file path and the mocked side effect of the command (file contents or
        exception).
    :param deps:
        Any dependencies to check that the host check is declared to have.
    :param failed_deps:
        Any dependencies to treat as failed.
    :return:
        The result of the check and the output from the check.
    """
    check = [c for c in CHECKS_BY_GROUP[group] if c.name == name][0]
    checks = []
    # Add any dependencies as guaranteed success.
    if deps:
        assert set(deps) == set(check.deps)
        for d in deps:
            if failed_deps and d in failed_deps:
                check_state = host_check.CheckState.FAILED
            else:
                check_state = host_check.CheckState.SUCCESS
            checks.append(
                host_check.Check(
                    name=d, func=lambda: (check_state, ""), deps=[]
                )
            )
    checks.append(check)

    with contextlib.ExitStack() as ctxs:
        # Set up the mocked subprocess command calls.
        if cmds:
            if not isinstance(cmds, list):
                cmds = [cmds]
            # If the side effect corresponds to the stdout from the subprocess,
            # this must be set on the mock process returned from subprocess.run().
            # Otherwise the side effect should apply directly to the
            # subprocess.run() call (e.g. for raising an exception).
            effects = []
            for _, effect in cmds:
                if isinstance(effect, str):
                    m = mock.MagicMock()
                    m.stdout = effect
                    effects.append(m)
                else:
                    # The commands with effect "None" are expected not to run:
                    if effect is not None:
                        effects.append(effect)
            mock_subproc = ctxs.enter_context(
                mock.patch("subprocess.run", side_effect=effects)
            )

        # Set up the mocked file contents.
        if files:
            if not isinstance(files, list):
                files = [files]
            # If the side effect corresponds to mocked file content, use
            # mock.mock_open() to handle mocking read(), readline(), etc.
            # Otherwise the side effect is applied directly to the open() call
            # (e.g. for raising an exception).
            effects = []
            for _, effect in files:
                if isinstance(effect, (str, bytes)):
                    effects.append(
                        mock.mock_open(read_data=effect).return_value
                    )
                # Skip file if effect is None
                elif effect is not None:
                    effects.append(effect)
            mock_open = ctxs.enter_context(
                mock.patch("builtins.open", side_effect=effects)
            )

        # Run the host check.
        result = host_check.perform_checks(checks)[name]

    # Check the expected commands were run.
    if cmds:
        actual_cmds = []
        for call in mock_subproc.call_args_list:
            cmd = call[0][0]
            if isinstance(cmd, str):
                actual_cmds.append(cmd)
            else:
                actual_cmds.append(" ".join(shlex.quote(x) for x in cmd))
        # Only expect the "not None" cmd_effects to be run.
        assert [c for c, e in cmds if e is not None] == actual_cmds

    # Check the expected files were read.
    if files:
        actual_files = [call[0][0] for call in mock_open.call_args_list]
        # Only expect the "not None" files to be read.
        assert [f for f, e in files if e is not None] == actual_files

    output = capsys.readouterr().out
    if deps:
        # Remove output from dependency checks.
        lines = output.splitlines(keepends=True)
        lines = lines[len(deps) :]
        output = "".join(lines)

    return result, output


# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------


class TestFlow:
    """Test the start-to-finish flow of the script."""

    @staticmethod
    def run_host_check(
        capsys,
        argv: List[str],
        failing_checks: List[str] = [],
        erroring_checks: List[str] = [],
    ) -> Tuple[int, str]:
        def perform_checks_mock(
            checks: List[Check],
        ) -> Mapping[str, CheckState]:
            results: Dict[str, CheckState] = {}
            checks_list = [c.name for c in checks]
            print("Checks:", ", ".join(checks_list))
            for check in checks_list:
                if check in failing_checks:
                    results[check] = CheckState.FAILED
                elif check in erroring_checks:
                    results[check] = CheckState.ERROR
                else:
                    results[check] = CheckState.SUCCESS
            return results

        with pytest.raises(SystemExit) as exc_info:
            with mock.patch.object(
                host_check, "perform_checks", perform_checks_mock
            ):
                host_check.main(argv)
        return exc_info.value.code, capsys.readouterr().out

    def test_no_args(self, capsys):
        """Test running host-check with no arguments."""
        exit_code, output = self.run_host_check(capsys, [])
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

============================================================================
XR platforms supported: xrd-control-plane, xrd-vrouter
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_plat_xrd(self, capsys):
        """Test running host-check with the xrd CP platform argument."""
        exit_code, output = self.run_host_check(
            capsys, ["-p", "xrd-control-plane"]
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

============================================================================
Host environment set up correctly for xrd-control-plane
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_plat_xrd_vrouter(self, capsys):
        """Test running host-check with the xrd-vrouter platform argument."""
        exit_code, output = self.run_host_check(capsys, ["-p", "xrd-vrouter"])
        cli_output = f"""\
==============================
Platform checks - xrd-vrouter
==============================
Checks: {BASE_CHECKS_STR}, {VROUTER_CHECKS_STR}

============================================================================
Host environment set up correctly for xrd-vrouter
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_docker_plat(self, capsys):
        """Test running host-check with the docker extra check."""
        exit_code, output = self.run_host_check(
            capsys, ["-p", "xrd-control-plane", "-e", "docker"]
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

============================================================================
Host environment set up correctly for xrd-control-plane
----------------------------------------------------------------------------
Extra checks passed: docker
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_xr_compose_plat(self, capsys):
        """Test running host-check with the xr-compose extra check."""
        exit_code, output = self.run_host_check(
            capsys, ["-p", "xrd-control-plane", "-e", "xr-compose"]
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

==============================
Extra checks
==============================

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
Host environment set up correctly for xrd-control-plane
----------------------------------------------------------------------------
Extra checks passed: xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_all_extra_checks_plat(self, capsys):
        """Test running host-check with all extra checks."""
        exit_code, output = self.run_host_check(
            capsys, ["-p", "xrd-control-plane", "-e", "xr-compose", "docker"]
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
Host environment set up correctly for xrd-control-plane
----------------------------------------------------------------------------
Extra checks passed: docker, xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_docker(self, capsys):
        """Test running host-check with the docker extra check."""
        exit_code, output = self.run_host_check(capsys, ["-e", "docker"])
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

============================================================================
XR platforms supported: xrd-control-plane, xrd-vrouter
----------------------------------------------------------------------------
Extra checks passed: docker
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_xr_compose(self, capsys):
        """Test running host-check with the xr-compose extra check."""
        exit_code, output = self.run_host_check(capsys, ["-e", "xr-compose"])
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

==============================
Extra checks
==============================

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
XR platforms supported: xrd-control-plane, xrd-vrouter
----------------------------------------------------------------------------
Extra checks passed: xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_all_extra_checks(self, capsys):
        """Test running host-check with all extra checks."""
        exit_code, output = self.run_host_check(
            capsys, ["-e", "xr-compose", "docker"]
        )
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
XR platforms supported: xrd-control-plane, xrd-vrouter
----------------------------------------------------------------------------
Extra checks passed: docker, xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_erroring(self, capsys):
        """Test running host-check with the docker extra check erroring."""
        exit_code, output = self.run_host_check(
            capsys, ["-e", "docker"], erroring_checks=["Docker daemon"]
        )
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

============================================================================
XR platforms supported: xrd-control-plane, xrd-vrouter
----------------------------------------------------------------------------
Extra checks errored: docker
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_plat_specified_check_failing(self, capsys):
        """Test a platform check failing when host-check is run with arguments."""
        exit_code, output = self.run_host_check(
            capsys,
            ["-p", "xrd-control-plane"],
            failing_checks=["Kernel version"],
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

============================================================================
!! Host NOT set up correctly for xrd-control-plane !!
============================================================================
"""
        assert output == cli_output
        assert exit_code == 1

    def test_plat_specified_check_erroring(self, capsys):
        """Test a platform check erroring when host-check is run with arguments."""
        exit_code, output = self.run_host_check(
            capsys,
            ["-p", "xrd-control-plane"],
            erroring_checks=["Kernel version"],
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

============================================================================
!! One or more platform checks could not be performed, see errors above !!
============================================================================
"""
        assert output == cli_output
        assert exit_code == 1

    def test_base_check_erroring(self, capsys):
        """Test a base check erroring when host-check is run without arguments."""
        exit_code, output = self.run_host_check(
            capsys,
            [],
            erroring_checks=["Kernel version"],
        )
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

============================================================================
!! One or more platform checks could not be performed, see errors above !!
============================================================================
"""
        assert output == cli_output
        assert exit_code == 1

    def test_no_plats_supported(self, capsys):
        """Test no platforms being supported when host-check is run without arguments."""
        exit_code, output = self.run_host_check(
            capsys, [], failing_checks=["Kernel version"]
        )
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

============================================================================
XR platforms NOT supported: xrd-control-plane, xrd-vrouter
============================================================================
"""
        assert output == cli_output
        assert exit_code == 1

    def test_one_plat_supported(self, capsys):
        """Test only one platform being supported."""
        exit_code, output = self.run_host_check(
            capsys, [], failing_checks=["Hugepages"]
        )
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

============================================================================
XR platforms supported: xrd-control-plane
XR platforms NOT supported: xrd-vrouter
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_not_supported(self, capsys):
        """Test an extra check not being supported when host-check is run without arguments."""
        exit_code, output = self.run_host_check(
            capsys, ["-e", "docker", "xr-compose"], failing_checks=["PyYAML"]
        )
        cli_output = f"""\
==============================
Platform checks
==============================

base checks
-----------------------
Checks: {BASE_CHECKS_STR}

xrd-control-plane checks
-----------------------
Checks: {CONTROL_PLANE_CHECKS_STR}

xrd-vrouter checks
-----------------------
Checks: {VROUTER_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
XR platforms supported: xrd-control-plane, xrd-vrouter
----------------------------------------------------------------------------
Extra checks passed: docker
Extra checks failed: xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 0

    def test_extra_check_failing(self, capsys):
        """Test a specified extra check failing."""
        exit_code, output = self.run_host_check(
            capsys,
            ["-p", "xrd-control-plane", "-e", "docker", "xr-compose"],
            failing_checks=["PyYAML"],
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
Host environment set up correctly for xrd-control-plane
----------------------------------------------------------------------------
Extra checks passed: docker
Extra checks failed: xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 1

    def test_extra_check_erroring_plat(self, capsys):
        """Test a specified extra check erroring."""
        exit_code, output = self.run_host_check(
            capsys,
            ["-p", "xrd-control-plane", "-e", "docker", "xr-compose"],
            erroring_checks=["PyYAML"],
        )
        cli_output = f"""\
==============================
Platform checks - xrd-control-plane
==============================
Checks: {BASE_CHECKS_STR}, {CONTROL_PLANE_CHECKS_STR}

==============================
Extra checks
==============================

docker checks
-----------------------
Checks: Docker client, Docker daemon, Docker supports d_type

xr-compose checks
-----------------------
Checks: docker-compose, PyYAML, Bridge iptables

============================================================================
Host environment set up correctly for xrd-control-plane
----------------------------------------------------------------------------
Extra checks passed: docker
Extra checks errored: xr-compose
============================================================================
"""
        assert output == cli_output
        assert exit_code == 1

    def test_unrecognized_arg(self, capsys):
        """Test running host-check with an unrecognized argument."""
        exit_code, output = self.run_host_check(capsys, ["philanthropy"])
        assert textwrap.dedent(output) == ""
        assert exit_code == 2


class _CheckTestBase:
    """Base test class for individual checks."""

    check_group: str
    check_name: str
    cmds: Optional[List[str]] = None
    files: Optional[List[str]] = None
    deps: Optional[List[str]] = None

    @classmethod
    def perform_check(
        cls,
        capsys,
        *,
        cmd_effects=None,
        read_effects=None,
        failed_deps=None,
    ) -> Tuple[CheckState, str]:
        """
        Perform the class's check with the given effects for each subproc cmd.

        :param cmd_effects:
            The effects for the subprocess command(s) that are (expected to be)
            run. Either a list or a single effect, where each effect is either
            stdout or an exception.
        :param read_effects:
            The effects when reading from file(s). Either a list or a single
            element, where each element is either the file contents or an
            exception.
        :param failed_deps:
            Any dependencies to treat as failed.
        :return:
            The result of the check and the output from the check.
        """
        if not isinstance(cmd_effects, list) and cmd_effects is not None:
            cmd_effects = [cmd_effects]
        if not isinstance(read_effects, list) and read_effects is not None:
            read_effects = [read_effects]
        if not isinstance(failed_deps, list) and failed_deps is not None:
            failed_deps = [failed_deps]

        if cmd_effects:
            cmds = list(zip(cls.cmds, cmd_effects))
        else:
            cmds = None
            assert not cmd_effects, "No commands declared on the class"
        if read_effects:
            files = list(zip(cls.files, read_effects))
        else:
            files = None

        return perform_check(
            capsys,
            group=cls.check_group,
            name=cls.check_name,
            cmds=cmds,
            files=files,
            deps=cls.deps,
            failed_deps=failed_deps,
        )


# -------------------------------------
# Base checks tests
# -------------------------------------


class TestArch(_CheckTestBase):
    """Tests for the architecture check."""

    check_group = "base"
    check_name = "CPU architecture"
    cmds = ["uname -m"]

    def test_success(self, capsys):
        """Test the architecture being correct."""
        result, output = self.perform_check(capsys, cmd_effects="x86_64")
        assert textwrap.dedent(output) == "PASS -- CPU architecture (x86_64)\n"
        assert result is CheckState.SUCCESS

    def test_incorrect_arch(self, capsys):
        """Test the incorrect architecture case."""
        result, output = self.perform_check(capsys, cmd_effects="arm64")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- CPU architecture
                    The CPU architecture is arm64, but XRd only supports: x86_64.
            """
        )
        assert result is CheckState.FAILED

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU architecture
                     Unable to check the CPU architecture with 'uname -m'.
                     XRd supports the following architectures: x86_64.
            """
        )
        assert result is CheckState.ERROR


class TestCPUCores(_CheckTestBase):
    """Tests for the CPU cores check."""

    check_group = "base"
    check_name = "CPU cores"
    cmds = ["lscpu"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, cmd_effects="CPU(s): 16 ")
        assert textwrap.dedent(output) == f"PASS -- CPU cores (16)\n"
        assert result is CheckState.SUCCESS

    def test_too_few_cpus(self, capsys):
        """Test there being too few available CPU cores."""
        result, output = self.perform_check(capsys, cmd_effects="CPU(s): 1 ")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- CPU cores
                    The number of available CPU cores is 1,
                    but at least 2 CPU cores are required.
            """
        )
        assert result is CheckState.FAILED

    def test_parse_error(self, capsys):
        """Test error when parsing output from 'lscpu'."""
        result, output = self.perform_check(
            capsys, cmd_effects="bananas taste awesome"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU cores
                     Unable to parse the output from 'lscpu' -
                     unable to check the number of available CPU cores.
                     At least 2 CPU cores are required.
            """
        )
        assert result is CheckState.ERROR

    def test_subproc_error(self, capsys):
        """Test subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU cores
                     Error running 'lscpu' to check the number of available CPU cores.
                     At least 2 CPU cores are required.
            """
        )
        assert result is CheckState.ERROR

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU cores
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR

    def test_timeout_error(self, capsys):
        """Test timeout error being raised."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=subprocess.TimeoutExpired(cmd=self.cmds, timeout=5),
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU cores
                     Unexpected error: Timed out while executing command: {" ".join(self.cmds)}
            """
        )
        assert result is CheckState.ERROR


class TestKernelVersion(_CheckTestBase):
    """Tests for the kernel version check."""

    check_group = "base"
    check_name = "Kernel version"
    cmds = ["uname -r"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, cmd_effects="4.1")
        assert textwrap.dedent(output) == "PASS -- Kernel version (4.1)\n"
        assert result is CheckState.SUCCESS

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Kernel version
                     Unable to check the kernel version with command 'uname -r' - must be at least version 4.0
            """
        )
        assert result is CheckState.ERROR

    def test_no_version_match(self, capsys):
        """Test failure to match the version in the output."""
        result, output = self.perform_check(
            capsys, cmd_effects="unexpected output"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Kernel version
                     Unable to check the kernel version with command 'uname -r' - must be at least version 4.0
            """
        )
        assert result is CheckState.ERROR

    def test_old_version(self, capsys):
        """Test the version being too old."""
        result, output = self.perform_check(capsys, cmd_effects="3.9.8")
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Kernel version
                    The kernel version is 3.9, but at least version 4.0 is required.
            """
        )
        assert result is CheckState.FAILED

    def test_rhel83_version(self, capsys):
        """Test the version being 4.18.0-240 on RHEL/CentOS 8.3."""
        result, output = self.perform_check(
            capsys, cmd_effects="4.18.0-240.el8"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Kernel version
                    The operating system appears to be RHEL/CentOS 8.3 (kernel version 4.18.0-240),
                    which is not supported due to a kernel bug.
                    Please upgrade/downgrade to a RHEL/CentOS version higher or lower than 8.3
            """
        )
        assert result is CheckState.FAILED

    def test_rhel82_version(self, capsys):
        """Test the version being 4.18.0-193 on RHEL/CentOS 8.2."""
        result, output = self.perform_check(
            capsys, cmd_effects="4.18.0-193.el8"
        )
        assert textwrap.dedent(output) == "PASS -- Kernel version (4.18)\n"
        assert result is CheckState.SUCCESS

    def test_generic_os_with_rhel83_kernel_version(self, capsys):
        """Test the version being 4.18.0-240 on a generic operating system."""
        result, output = self.perform_check(
            capsys, cmd_effects="4.18.0-240.generic"
        )
        assert textwrap.dedent(output) == "PASS -- Kernel version (4.18)\n"
        assert result is CheckState.SUCCESS


class TestBaseKernelModules(_CheckTestBase):
    """Tests for the base kernel modules check."""

    check_group = "base"
    check_name = "Base kernel modules"
    deps = ["Kernel version"]
    cmds = [
        "grep -q /dummy.ko /lib/modules/*/modules.*",
        "grep -q /nf_tables.ko /lib/modules/*/modules.*",
    ]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, cmd_effects=["", ""])
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            PASS -- Base kernel modules
                    Installed module(s): dummy, nf_tables
            """
        )
        assert result is CheckState.SUCCESS

    def test_missing_nf_tables(self, capsys):
        """Test missing the nf_tables kernel module."""
        result, output = self.perform_check(
            capsys, cmd_effects=["", subprocess.SubprocessError(1, "")]
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- Base kernel modules
                    Missing kernel module(s): nf_tables
                    (checked in /lib/modules/*/modules.*).
                    It may be possible to install using your distro's package manager.
            """
        )
        assert result is CheckState.FAILED

    def test_missing_dummy(self, capsys):
        """Test missing the dummy kernel module."""
        result, output = self.perform_check(
            capsys, cmd_effects=[subprocess.SubprocessError(1, ""), ""]
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- Base kernel modules
                    Missing kernel module(s): dummy
                    (checked in /lib/modules/*/modules.*).
                    It may be possible to install using your distro's package manager.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=["", Exception("test exception")]
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- Base kernel modules
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR

    def test_timeout_error(self, capsys):
        """Test timeout error being raised."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=subprocess.TimeoutExpired(cmd=self.cmds, timeout=5),
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- Base kernel modules
                     Unexpected error: Timed out while executing command: {" ".join(self.cmds)}
            """
        )
        assert result is CheckState.ERROR

    def test_failed_dependency(self, capsys):
        """Test a dependency failure."""
        result, output = self.perform_check(capsys, failed_deps=self.deps)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            SKIP -- Base kernel modules
                    Skipped due to failed checks: Kernel version
            """
        )
        assert result is CheckState.SKIPPED


class TestCgroups(_CheckTestBase):
    """Tests for the cgroups check."""

    check_group = "base"
    check_name = "Cgroups"
    cmds = [
        "findmnt /sys/fs/cgroup -t cgroup2",
        "findmnt /sys/fs/cgroup/memory -t cgroup",
        "findmnt /sys/fs/cgroup/systemd -t cgroup",
        "findmnt /sys/fs/cgroup/memory -t cgroup",
        "findmnt /sys/fs/cgroup/pids -t cgroup",
        "findmnt /sys/fs/cgroup/cpu -t cgroup",
        "findmnt /sys/fs/cgroup/cpuset -t cgroup",
    ]

    @staticmethod
    @pytest.fixture(scope="class", autouse=True)
    def mock_cgroup_dirs():
        with mock.patch("glob.glob", return_value=["/sys/fs/cgroup/memory"]):
            yield

    def test_v1_success(self, capsys):
        """Test the cgroups v1 success case."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                mock.Mock(returncode=1),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Cgroups (v1)
            """
        )
        assert result is CheckState.SUCCESS

    def test_unknown_version(self, capsys):
        """Test the case where the cgroups version is unrecognised."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[mock.Mock(returncode=1), mock.Mock(returncode=1)],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Cgroups
                     Error trying to determine the cgroups version - /sys/fs/cgroup is expected to
                     contain cgroup v1 mounts.
            """
        )
        assert result is CheckState.ERROR

    def test_v2_info(self, capsys):
        """Test the case where v2 cgroups are in use."""
        with mock.patch("builtins.open", mock.mock_open(read_data="memory")):
            result, output = self.perform_check(
                capsys, cmd_effects=[mock.Mock(returncode=0), None]
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            INFO -- Cgroups
                    Cgroups v2 is in use - this is not supported for production environments.
            """
        )
        assert result is CheckState.NEUTRAL

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Cgroups
                     Error trying to determine the cgroups version - /sys/fs/cgroup is expected to
                     contain cgroup v1 mounts.
            """
        )
        assert result is CheckState.ERROR

    def test_systemd_mount_error(self, capsys):
        """Test case where systemd mount isn't present."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                mock.Mock(returncode=1),
                mock.Mock(returncode=0),
                mock.Mock(returncode=1),  # /sys/fs/cgroup/systemd
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Cgroups
                    These cgroup mounts do not exist on the host: systemd.
                    These mounts are required to run XRd.
                    If your distro doesn't use systemd, manually add the systemd cgroup mount with:
                        sudo mkdir /sys/fs/cgroup/systemd
                        sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd
            """
        )
        assert result is CheckState.FAILED

    def test_pids_mount_error(self, capsys):
        """Test case where systemd mount isn't present."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                mock.Mock(returncode=1),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=1),  # /sys/fs/cgroup/pids
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Cgroups
                    These cgroup mounts do not exist on the host: pids.
                    These mounts are required to run XRd.
            """
        )
        assert result is CheckState.FAILED

    def test_systemd_cpu_mount_error(self, capsys):
        """Test case where systemd mount isn't present."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                mock.Mock(returncode=1),
                mock.Mock(returncode=0),
                mock.Mock(returncode=1),  # /sys/fs/cgroup/systemd
                mock.Mock(returncode=0),
                mock.Mock(returncode=0),
                mock.Mock(returncode=1),  # /sys/fs/cgroup/cpu
                mock.Mock(returncode=0),
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Cgroups
                    These cgroup mounts do not exist on the host: systemd, cpu.
                    These mounts are required to run XRd.
                    If your distro doesn't use systemd, manually add the systemd cgroup mount with:
                        sudo mkdir /sys/fs/cgroup/systemd
                        sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd
            """
        )
        assert result is CheckState.FAILED


class _TestInotifyLimitsBase(_CheckTestBase):
    """Base class for inotify limit checks."""

    check_group = "base"
    inotify_param: str

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, read_effects="10000000")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            PASS -- {self.check_name}
                    10000000 - this is expected to be sufficient for 2500 XRd instance(s).
            """
        )
        assert result is CheckState.SUCCESS

    def test_too_low(self, capsys):
        """Test the limit being too low."""
        result, output = self.perform_check(capsys, read_effects="3000")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- {self.check_name}
                    The kernel parameter fs.inotify.{self.inotify_param} is set to 3000 but
                    should be at least 4000 (sufficient for a single instance) - the
                    recommended value is 64000.
                    This can be addressed by adding 'fs.inotify.{self.inotify_param}=64000'
                    to /etc/sysctl.conf or in a dedicated conf file under /etc/sysctl.d/.
                    For a temporary fix, run:
                      sysctl -w fs.inotify.{self.inotify_param}=64000
            """
        )
        assert result is CheckState.FAILED

    def test_warning_level(self, capsys):
        """Test the limit being not too low but recommended to be higher."""
        result, output = self.perform_check(capsys, read_effects="7000")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- {self.check_name}
                    The kernel parameter fs.inotify.{self.inotify_param} is set to 7000 -
                    this is expected to be sufficient for 1 XRd instance(s).
                    The recommended value is 64000.
                    This can be addressed by adding 'fs.inotify.{self.inotify_param}=64000'
                    to /etc/sysctl.conf or in a dedicated conf file under /etc/sysctl.d/.
                    For a temporary fix, run:
                      sysctl -w fs.inotify.{self.inotify_param}=64000
            """
        )
        assert result is CheckState.WARNING

    def test_error(self, capsys):
        """Test error being raised."""
        result, output = self.perform_check(capsys, read_effects=Exception)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- {self.check_name}
                     Failed to check inotify resource limits by reading
                     /proc/sys/fs/inotify/{self.inotify_param}.
                     The kernel parameter fs.inotify.{self.inotify_param} should be set to at least 4000
                     (sufficient for a single instance) - the recommended value is 64000.
                     This can be addressed by adding 'fs.inotify.{self.inotify_param}=64000'
                     to /etc/sysctl.conf or in a dedicated conf file under /etc/sysctl.d/.
                     For a temporary fix, run:
                       sysctl -w fs.inotify.{self.inotify_param}=64000
            """
        )
        assert result is CheckState.ERROR


class TestInotifyInstances(_TestInotifyLimitsBase):
    """Tests for inotify instances check (inherited from base class)."""

    inotify_param = "max_user_instances"
    check_name = "Inotify max user instances"
    files = ["/proc/sys/fs/inotify/max_user_instances"]


class TestInotifyWatches(_TestInotifyLimitsBase):
    """Tests for inotify watches check (inherited from base class)."""

    inotify_param = "max_user_watches"
    check_name = "Inotify max user watches"
    files = ["/proc/sys/fs/inotify/max_user_watches"]


class TestCorePattern(_CheckTestBase):
    """Tests for the core pattern check."""

    check_group = "base"
    check_name = "Core pattern"
    files = ["/proc/sys/kernel/core_pattern"]

    def test_managed_by_xr(self, capsys):
        """Test the managed by XR case."""
        result, output = self.perform_check(
            capsys, read_effects="no leading pipe"
        )
        assert (
            textwrap.dedent(output)
            == "INFO -- Core pattern (core files managed by XR)\n"
        )
        assert result is CheckState.NEUTRAL

    def test_managed_by_host(self, capsys):
        """Test the managed by host case."""
        result, output = self.perform_check(capsys, read_effects="| piped")
        assert (
            textwrap.dedent(output)
            == "INFO -- Core pattern (core files managed by the host)\n"
        )
        assert result is CheckState.NEUTRAL

    def test_error(self, capsys):
        """Test error being raised."""
        result, output = self.perform_check(capsys, read_effects=Exception)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            INFO -- Core pattern
                    Failed to read /proc/sys/kernel/core_pattern - unable to determine
                    whether core files are managed by XR or the host.
            """
        )
        assert result is CheckState.NEUTRAL


class TestASLR(_CheckTestBase):
    """Tests for ASLR check."""

    check_group = "base"
    check_name = "ASLR"
    files = ["/proc/sys/kernel/randomize_va_space"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, read_effects="2")
        assert textwrap.dedent(output) == "PASS -- ASLR (full randomization)\n"
        assert result is CheckState.SUCCESS

    def test_read_error(self, capsys):
        """Test the limit being too low."""
        result, output = self.perform_check(capsys, read_effects=Exception)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- ASLR
                     Failed to read /proc/sys/kernel/randomize_va_space, which controls ASLR
                     (Address-Space Layout Randomization).
                     It is recommended for this kernel parameter to be set to 2 (full
                     randomization) for security reasons. This can be done by adding
                     'kernel.randomize_va_space=2' to /etc/sysctl.conf or in a dedicated conf
                     file under /etc/sysctl.d/.
                     For a temporary fix, run:
                       sysctl -w kernel.randomize_va_space=2
            """
        )
        assert result is CheckState.ERROR

    def test_unexpected_value(self, capsys):
        """Test the file containing an unexpected value."""
        result, output = self.perform_check(capsys, read_effects="unexpected")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- ASLR
                     Failed to read /proc/sys/kernel/randomize_va_space, which controls ASLR
                     (Address-Space Layout Randomization).
                     It is recommended for this kernel parameter to be set to 2 (full
                     randomization) for security reasons. This can be done by adding
                     'kernel.randomize_va_space=2' to /etc/sysctl.conf or in a dedicated conf
                     file under /etc/sysctl.d/.
                     For a temporary fix, run:
                       sysctl -w kernel.randomize_va_space=2
            """
        )
        assert result is CheckState.ERROR

    def test_not_enabled(self, capsys):
        """Test the limit being not too low but recommended to be higher."""
        result, output = self.perform_check(capsys, read_effects="1")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- ASLR
                    The kernel paramater kernel.randomize_va_space, which controls ASLR
                    (Address-Space Layout Randomization), is set to 1.
                    It is recommended for this kernel parameter to be set to 2 (full
                    randomization) for security reasons. This can be done by adding
                    'kernel.randomize_va_space=2' to /etc/sysctl.conf or in a dedicated conf
                    file under /etc/sysctl.d/.
                    For a temporary fix, run:
                      sysctl -w kernel.randomize_va_space=2
            """
        )
        assert result is CheckState.WARNING


class TestLSMs(_CheckTestBase):
    """Tests for Linux Security Modules check."""

    check_group = "base"
    check_name = "Linux Security Modules"
    files = ["/sys/kernel/security/apparmor/profiles", "/etc/selinux/config"]

    def test_neither_enabled(self, capsys):
        """
        Test when config files read, they indicate LSMs are disabled or not
        installed.
        """
        expected = textwrap.dedent(
            f"""\
            INFO -- Linux Security Modules (No LSMs are enabled)
            """
        )
        result, output = self.perform_check(
            capsys, read_effects=[FileNotFoundError, FileNotFoundError]
        )
        assert textwrap.dedent(output) == expected
        assert result is CheckState.NEUTRAL

        result, output = self.perform_check(
            capsys, read_effects=["", "SELINUX=disabled"]
        )
        assert textwrap.dedent(output) == expected
        assert result is CheckState.NEUTRAL

    def test_apparmor_enabled(self, capsys):
        """Test AppArmor config set to enabled."""
        result, output = self.perform_check(
            capsys,
            read_effects=["nvidia_modprobe (enforce)", FileNotFoundError],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- Linux Security Modules
                    AppArmor is enabled. XRd is currently unable to run with the
                    default docker profile, but can be run with
                    '--security-opt apparmor=unconfined' or equivalent.
                    However, some features might not work, such as ZTP.
            """
        )
        assert result is CheckState.WARNING

    def test_selinux_enabled(self, capsys):
        """Test SELinux config set to enabled."""
        expected = textwrap.dedent(
            f"""\
            INFO -- Linux Security Modules
                    SELinux is enabled. XRd is currently unable to run with the
                    default policy, but can be run with
                    '--security-opt label=disable' or equivalent.
            """
        )
        result, output = self.perform_check(
            capsys, read_effects=[FileNotFoundError, "SELINUX=enforcing"]
        )
        assert textwrap.dedent(output) == expected
        assert result is CheckState.NEUTRAL

        result, output = self.perform_check(
            capsys, read_effects=["", "SELINUX=enforcing"]
        )
        assert textwrap.dedent(output) == expected
        assert result is CheckState.NEUTRAL

    def test_both_enabled(self, capsys):
        """Test the case where both AppArmor and SELinux are enabled."""
        result, output = self.perform_check(
            capsys,
            read_effects=["nvidia_modprobe (enforce)", "SELINUX=enforcing"],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- Linux Security Modules
                    AppArmor is enabled. XRd is currently unable to run with the
                    default docker profile, but can be run with
                    '--security-opt apparmor=unconfined' or equivalent.
                    However, some features might not work, such as ZTP.
                    SELinux is enabled. XRd is currently unable to run with the
                    default policy, but can be run with
                    '--security-opt label=disable' or equivalent.
            """
        )
        assert result is CheckState.WARNING


class TestRealtimeGroupSched(_CheckTestBase):
    """Tests for Real-time Group Scheduling disabled check"""

    check_group = "xrd-vrouter"
    check_name = "Real-time Group Scheduling"
    files = ["/proc/sys/kernel/sched_rt_runtime_us"]

    def test_v1_disabled_in_kernel_config(self, capsys):
        """Test the v1 case where disabled in kernel config"""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=1
        ), mock.patch("os.path.exists", return_value=False):
            result, output = self.perform_check(capsys, read_effects=None)
        assert (
            textwrap.dedent(output)
            == "PASS -- Real-time Group Scheduling (disabled in kernel config)\n"
        )
        assert result is CheckState.SUCCESS

    def test_v1_disabled_at_runtime(self, capsys):
        """Test the v1 case where disabled at runtime"""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=1
        ), mock.patch("os.path.exists", return_value=True):
            result, output = self.perform_check(capsys, read_effects="-1")
        assert (
            textwrap.dedent(output)
            == "PASS -- Real-time Group Scheduling (disabled at runtime)\n"
        )
        assert result is CheckState.SUCCESS

    def test_v1_read_error(self, capsys):
        """Test the limit being too low."""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=1
        ), mock.patch("os.path.exists", return_value=True):
            result, output = self.perform_check(capsys, read_effects=Exception)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Real-time Group Scheduling
                     Failed to read /proc/sys/kernel/sched_rt_runtime_us, unable to check if
                     real-time group scheduling is disabled.
                     Running with real-time group scheduling enabled is not supported.
                     If real-time group scheduling (RT_GROUP_SCHED) is configured in the kernel,
                     it is required that this feature is disabled at runtime by adding
                     'kernel.sched_rt_runtime_us=-1' to /etc/sysctl.conf or in a dedicated conf
                     file under /etc/sysctl.d/.
                     For a temporary fix, run:
                       sysctl -w kernel.sched_rt_runtime_us=-1
            """
        )
        assert result is CheckState.ERROR

    def test_v1_failure_enabled_at_runtime(self, capsys):
        """Test the check fails in the v1 case where enabled at runtime"""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=1
        ), mock.patch("os.path.exists", return_value=True):
            result, output = self.perform_check(capsys, read_effects="950000")
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Real-time Group Scheduling
                    The kernel parameter kernel.sched_rt_runtime_us is set to 950000
                    but must be disabled by setting it to '-1'.
                    Running with real-time group scheduling enabled is not supported.
                    If real-time group scheduling (RT_GROUP_SCHED) is configured in the kernel,
                    it is required that this feature is disabled at runtime by adding
                    'kernel.sched_rt_runtime_us=-1' to /etc/sysctl.conf or in a dedicated conf
                    file under /etc/sysctl.d/.
                    For a temporary fix, run:
                      sysctl -w kernel.sched_rt_runtime_us=-1
            """
        )
        assert result is CheckState.FAILED

    def test_v2_disabled_in_kernel_config(self, capsys):
        """Test the v2 case where disabled in kernel config"""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=2
        ), mock.patch("os.path.exists", return_value=False):
            result, output = self.perform_check(capsys, read_effects=None)
        assert (
            textwrap.dedent(output)
            == "PASS -- Real-time Group Scheduling (disabled in kernel config)\n"
        )
        assert result is CheckState.SUCCESS

    def test_v2_disabled_at_runtime(self, capsys):
        """Test the v2 case where disabled at runtime"""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=2
        ), mock.patch("os.path.exists", return_value=True):
            result, output = self.perform_check(capsys, read_effects="-1")
        assert (
            textwrap.dedent(output)
            == "PASS -- Real-time Group Scheduling (disabled at runtime)\n"
        )
        assert result is CheckState.SUCCESS

    def test_v2_failure_enabled_at_runtime(self, capsys):
        """Test the check fails in the v2 case where enabled at runtime"""
        with mock.patch(
            "host_check._get_cgroup_version", return_value=2
        ), mock.patch("os.path.exists", return_value=True):
            result, output = self.perform_check(capsys, read_effects="950000")
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Real-time Group Scheduling
                    The kernel parameter kernel.sched_rt_runtime_us is set to 950000
                    but must be disabled by setting it to '-1'.
                    Running with real-time group scheduling enabled is not supported.
                    If real-time group scheduling (RT_GROUP_SCHED) is configured in the kernel,
                    it is required that this feature is disabled at runtime by adding
                    'kernel.sched_rt_runtime_us=-1' to /etc/sysctl.conf or in a dedicated conf
                    file under /etc/sysctl.d/.
                    For a temporary fix, run:
                      sysctl -w kernel.sched_rt_runtime_us=-1
            """
        )
        assert result is CheckState.FAILED


class TestSocketParameters(_CheckTestBase):
    """Tests for Socket Kernel Parameters check."""

    check_group = "base"
    check_name = "Socket kernel parameters"
    files = [
        "/proc/sys/net/core/netdev_max_backlog",
        "/proc/sys/net/core/optmem_max",
        "/proc/sys/net/core/rmem_default",
        "/proc/sys/net/core/rmem_max",
        "/proc/sys/net/core/wmem_default",
        "/proc/sys/net/core/wmem_max",
    ]

    def test_matching_values(self, capsys):
        """Test when all values precisely match, the check passes."""
        minimum_values = [
            "300000",
            "67108864",
            "67108864",
            "67108864",
            "67108864",
            "67108864",
        ]
        result, output = self.perform_check(
            capsys, read_effects=minimum_values
        )
        assert (
            textwrap.dedent(output)
            == "PASS -- Socket kernel parameters (valid settings)\n"
        )
        assert result is CheckState.SUCCESS

    def test_higher_values(self, capsys):
        """Test when values are higher, the check passes."""
        higher_values = [
            "400000",
            "67108865",
            "67108874",
            "67108964",
            "67109864",
            "67118864",
        ]
        result, output = self.perform_check(capsys, read_effects=higher_values)
        assert (
            textwrap.dedent(output)
            == "PASS -- Socket kernel parameters (valid settings)\n"
        )
        assert result is CheckState.SUCCESS

    def test_lower_values(self, capsys):
        """Test when values are lower, the check warns."""
        lower_values = [
            "1000",
            "20480",
            "212992",
            "212992",
            "212992",
            "212992",
        ]
        result, output = self.perform_check(capsys, read_effects=lower_values)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- Socket kernel parameters
                    The kernel socket parameters are insufficient for running XRd in a
                    production deployment. They may be used in a lab deployment, but must
                    be increased to the required minimums for production deployment.
                    Lower values may result in XR IPC loss and unpredictable behavior,
                    particularly at higher scale.

                    The required minimum settings are:
                        net.core.netdev_max_backlog=300000
                        net.core.optmem_max=67108864
                        net.core.rmem_default=67108864
                        net.core.rmem_max=67108864
                        net.core.wmem_default=67108864
                        net.core.wmem_max=67108864

                    The current host settings are:
                        net.core.netdev_max_backlog=1000
                        net.core.optmem_max=20480
                        net.core.rmem_default=212992
                        net.core.rmem_max=212992
                        net.core.wmem_default=212992
                        net.core.wmem_max=212992

                    Values can be changed by adding e.g.
                    'net.core.rmem_default=67108864' to /etc/sysctl.conf or
                    in a dedicated conf file under /etc/sysctl.d/.
                    Or for a temporary fix, running e.g.:
                      sysctl -w net.core.rmem_default=67108864
            """
        )
        assert result is CheckState.WARNING

    def test_read_failure(self, capsys):
        """Test read failure on socket parameter"""
        error_values = [
            "300000",
            "67108864",
            "67108864",
            Exception,
        ]
        result, output = self.perform_check(capsys, read_effects=error_values)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- Socket kernel parameters
                     Failed to read socket kernel parameter /proc/sys/net/core/rmem_max.
            """
        )
        assert result is CheckState.ERROR


class TestUDPParameters(_CheckTestBase):
    """Tests for UDP Kernel Parameters check."""

    check_group = "base"
    check_name = "UDP kernel parameters"
    files = ["/proc/sys/net/ipv4/udp_mem"]

    def test_matching_values(self, capsys):
        """Test when all values precisely match, the check passes."""
        result, output = self.perform_check(
            capsys, read_effects="1124736 10000000 67108864"
        )
        assert (
            textwrap.dedent(output)
            == "PASS -- UDP kernel parameters (valid settings)\n"
        )
        assert result is CheckState.SUCCESS

    def test_higher_values(self, capsys):
        """Test when values are higher, the check passes."""
        result, output = self.perform_check(
            capsys, read_effects="1124737 20000000 67108868"
        )
        assert (
            textwrap.dedent(output)
            == "PASS -- UDP kernel parameters (valid settings)\n"
        )
        assert result is CheckState.SUCCESS

    def test_lower_values(self, capsys):
        """Test when values are lower, the check warns."""

        result, output = self.perform_check(
            capsys, read_effects="767055 1022741 1534110"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- UDP kernel parameters
                    The kernel UDP parameters are insufficient for running XRd in a
                    production deployment. They may be used in a lab deployment, but must
                    be increased to the required minimums for production deployment.
                    Lower values may result in XR IPC loss and unpredictable behavior,
                    particularly at higher scale.

                    The required minimum settings are:
                        net.ipv4.udp_mem=1124736 10000000 67108864
                    The current host settings are:
                        net.ipv4.udp_mem=767055 1022741 1534110
                    Values can be changed by adding
                    'net.ipv4.udp_mem=1124736 10000000 67108864' to /etc/sysctl.conf or
                    in a dedicated conf file under /etc/sysctl.d/.
                    Or for a temporary fix, running:
                      sysctl -w net.ipv4.udp_mem='1124736 10000000 67108864'
            """
        )
        assert result is CheckState.WARNING

        result, output = self.perform_check(
            capsys, read_effects="1124736 1022741 1534110"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- UDP kernel parameters
                    The kernel UDP parameters are insufficient for running XRd in a
                    production deployment. They may be used in a lab deployment, but must
                    be increased to the required minimums for production deployment.
                    Lower values may result in XR IPC loss and unpredictable behavior,
                    particularly at higher scale.

                    The required minimum settings are:
                        net.ipv4.udp_mem=1124736 10000000 67108864
                    The current host settings are:
                        net.ipv4.udp_mem=1124736 1022741 1534110
                    Values can be changed by adding
                    'net.ipv4.udp_mem=1124736 10000000 67108864' to /etc/sysctl.conf or
                    in a dedicated conf file under /etc/sysctl.d/.
                    Or for a temporary fix, running:
                      sysctl -w net.ipv4.udp_mem='1124736 10000000 67108864'
            """
        )
        assert result is CheckState.WARNING

        result, output = self.perform_check(
            capsys, read_effects="1124736 10000000 1534110"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- UDP kernel parameters
                    The kernel UDP parameters are insufficient for running XRd in a
                    production deployment. They may be used in a lab deployment, but must
                    be increased to the required minimums for production deployment.
                    Lower values may result in XR IPC loss and unpredictable behavior,
                    particularly at higher scale.

                    The required minimum settings are:
                        net.ipv4.udp_mem=1124736 10000000 67108864
                    The current host settings are:
                        net.ipv4.udp_mem=1124736 10000000 1534110
                    Values can be changed by adding
                    'net.ipv4.udp_mem=1124736 10000000 67108864' to /etc/sysctl.conf or
                    in a dedicated conf file under /etc/sysctl.d/.
                    Or for a temporary fix, running:
                      sysctl -w net.ipv4.udp_mem='1124736 10000000 67108864'
            """
        )
        assert result is CheckState.WARNING

    def test_read_failure(self, capsys):
        """Test read failure on socket parameter"""
        result, output = self.perform_check(capsys, read_effects=Exception)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- UDP kernel parameters
                     Failed to read UDP kernel parameter /proc/sys/net/ipv4/udp_mem.
            """
        )
        assert result is CheckState.ERROR


class TestKernelModuleParameters(_CheckTestBase):
    """Tests for default Kernel Parameters check."""

    check_group = "base"
    check_name = "Kernel module parameters"
    files = [
        "/sys/module/vfio_pci/parameters/nointxmask",
        "/sys/module/vfio_pci/parameters/disable_idle_d3",
        "/sys/module/vfio_pci/parameters/enable_sriov",
        "/sys/module/igb_uio/parameters/intr_mode",
    ]
    cmds = [
        "lsmod | grep -q '^vfio_pci '",  # loaded
        "grep -q /vfio-pci.ko /lib/modules/*/modules.builtin",  # builtin
        "modinfo --field parm vfio_pci",
        "lsmod | grep -q '^igb_uio '",  # loaded
        "grep -q /igb_uio.ko /lib/modules/*/modules.builtin",  # builtin
        "modinfo --field parm igb_uio",
    ]
    # Output of 'modinfo --field parm vfio_pci' with all parameters enabled
    vfio_pci_parms = """\
ids:Initial PCI IDs to add to the vfio driver, format is "vendor:device...
nointxmask:Disable support for PCI 2.3 style INTx masking.  If this ...
disable_idle_d3:Disable using the PCI D3 low power state for ...
enable_sriov:Enable support for SR-IOV configuration.  Enabling S...
disable_denylist:Disable use of device denylist. Disabling the deny...
        """
    # Output of 'modinfo --field parm igb_uio' with all parameters enabled
    igb_uio_parms = """\
intr_mode:igb_uio interrupt mode (default=msix):
    msix       Use MSIX interrupt
    msi        Use MSI interrupt
    legacy     Use Legacy interrupt

 (charp)
wc_activate:Activate support for write combining (WC) (default=0)
    0 - disable
    other - enable
 (int)
        """

    def test_success(self, capsys):
        """
        Test the success case.
        Both modules loaded and all parameters supported and enabled with
        default values
        """

        cmd_outputs = [
            "",
            None,
            self.vfio_pci_parms,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = ["N", "N", "N", "msix"]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Kernel module parameters
                    Kernel modules loaded with expected parameters.
            """
        )
        assert result is CheckState.SUCCESS

    def test_one_parm_disable(self, capsys):
        """Test one parameter not supported by the kernel."""
        vfio_pci_test_parm = """\
ids:Initial PCI IDs to add to the vfio driver, format is "vendor:device...
nointxmask:Disable support for PCI 2.3 style INTx masking.  If this ...
disable_idle_d3:Disable using the PCI D3 low power state for ...
disable_denylist:Disable use of device denylist. Disabling the deny...
        """
        cmd_outputs = [
            "",
            None,
            vfio_pci_test_parm,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = ["N", "N", None, "msix"]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Kernel module parameters
                    Kernel modules loaded with expected parameters.
            """
        )
        assert result is CheckState.SUCCESS

    def test_one_parm_non_default(self, capsys):
        """Test one parameter having a non-default value."""
        cmd_outputs = [
            "",
            None,
            self.vfio_pci_parms,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = ["N", "Y", "N", "msix"]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            WARN -- Kernel module parameters
                    XRd has not been tested with these kernel module parameters.
                    For kernel module: vfio-pci
                       The expected value for parameter disable_idle_d3 is N, but it is set to Y
            """
        )
        assert result is CheckState.WARNING

    def test_two_parm_non_default(self, capsys):
        """Test two parameters having non-default values."""
        cmd_outputs = [
            "",
            None,
            self.vfio_pci_parms,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = ["N", "Y", "N", "legacy"]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            WARN -- Kernel module parameters
                    XRd has not been tested with these kernel module parameters.
                    For kernel module: vfio-pci
                       The expected value for parameter disable_idle_d3 is N, but it is set to Y
                    For kernel module: igb_uio
                       The expected value for parameter intr_mode is msix/(null), but it is set to legacy
            """
        )
        assert result is CheckState.WARNING

    def test_one_module_not_loaded(self, capsys):
        """Test where one module is not loaded."""
        cmd_outputs = [
            subprocess.SubprocessError(1, ""),
            subprocess.SubprocessError(1, ""),
            None,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = [None, None, None, "msix"]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Kernel module parameters
                    Kernel modules loaded with expected parameters.
            """
        )
        assert result is CheckState.SUCCESS

    def test_both_module_not_loaded(self, capsys):
        """Test where both modules are not loaded."""
        cmd_outputs = [
            subprocess.SubprocessError(1, ""),
            subprocess.SubprocessError(1, ""),
            None,
            subprocess.SubprocessError(1, ""),
            subprocess.SubprocessError(1, ""),
            None,
        ]
        files_content = [None, None, None, None]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Kernel module parameters
                    Kernel modules loaded with expected parameters.
            """
        )
        assert result is CheckState.SUCCESS

    def test_parm_file_not_found(self, capsys):
        """Test one parameter file not being found"""
        cmd_outputs = [
            "",
            None,
            self.vfio_pci_parms,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = ["N", "N", "N", FileNotFoundError]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            WARN -- Kernel module parameters
                    XRd has not been tested with these kernel module parameters.
                    For kernel module: igb_uio
                       Failed to check value for parameter: intr_mode
            """
        )
        assert result is CheckState.WARNING

    def test_parm_null_value(self, capsys):
        """Test one parameter having (null) value"""
        cmd_outputs = [
            "",
            None,
            self.vfio_pci_parms,
            "",
            None,
            self.igb_uio_parms,
        ]
        files_content = ["N", "N", "N", "(null)"]
        result, output = self.perform_check(
            capsys, cmd_effects=cmd_outputs, read_effects=files_content
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Kernel module parameters
                    Kernel modules loaded with expected parameters.
            """
        )
        assert result is CheckState.SUCCESS


# -------------------------------------
# Platform checks tests
# -------------------------------------


class TestRAM(_CheckTestBase):
    """Tests for the RAM check."""

    check_group = "xrd-control-plane"
    check_name = "RAM"
    cmds = ["free -b"]

    def test_success(self, capsys):
        """Test the success case."""
        cmd_output = """\
              total        used        free      shared  buff/cache   available
Mem:    17048223744 14166241280  2647126016    18145280   234856448  2745040896
Swap:   31798079488  2008911872 29789167616
        """
        result, output = self.perform_check(capsys, cmd_effects=cmd_output)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- RAM
                    Available RAM is 2.6 GiB.
                    This is estimated to be sufficient for 1 XRd instance(s), although memory
                    usage depends on the running configuration.
                    Note that any swap that may be available is not included.
            """
        )
        assert result is CheckState.SUCCESS

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- RAM
                     The command 'free -b' failed - unable to determine the available RAM on
                     the host.
                     Each XRd instance is expected to require 2 GiB of RAM for normal use.
            """
        )
        assert result is CheckState.ERROR

    def test_no_match(self, capsys):
        """Test failure to parse free memory from the output."""
        result, output = self.perform_check(
            capsys, cmd_effects="unexpected output"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- RAM
                     Failed to parse the output from 'free -b' - unable to determine the
                     available RAM on the host.
                     Each XRd instance is expected to require 2 GiB of RAM for normal use.
            """
        )
        assert result is CheckState.ERROR

    def test_too_low(self, capsys):
        """Test the available memory being too low."""
        cmd_output = """\
              total        used        free      shared  buff/cache   available
Mem:    17048223744 14166241280  2647126016    18145280   234856448  1745040896
Swap:   31798079488  2008911872 29789167616
        """
        result, output = self.perform_check(capsys, cmd_effects=cmd_output)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            WARN -- RAM
                    The available RAM on the host (1.6 GiB) may be insufficient to run XRd.
                    Each XRd instance is expected to require 2 GiB of RAM for normal use.
                    Note that this does not include any swap that may be available.
            """
        )
        assert result is CheckState.WARNING

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- RAM
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestCPUExtensions(_CheckTestBase):
    """Tests for the CPU extensions check."""

    check_group = "xrd-vrouter"
    check_name = "CPU extensions"
    cmds = ["lscpu"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(
            capsys, cmd_effects="Flags: ssse3 sse4_1 sse4_2"
        )
        assert (
            textwrap.dedent(output)
            == f"PASS -- CPU extensions (sse4_1, sse4_2, ssse3)\n"
        )
        assert result is CheckState.SUCCESS

    def test_parse_error(self, capsys):
        """Test the case where the CPU extensions cannot be parsed."""
        result, output = self.perform_check(capsys, cmd_effects="no match")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU extensions
                     Unable to parse the output from 'lscpu' - unable to check
                     for the required CPU extensions: sse4_1, sse4_2, ssse3
                     All of these extensions must be installed.
            """
        )
        assert result is CheckState.ERROR

    def test_missing_extensions(self, capsys):
        """Test some extensions being missing."""
        result, output = self.perform_check(capsys, cmd_effects="Flags: ssse3")
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- CPU extensions
                    Missing CPU extension(s): sse4_1, sse4_2
                    Please install the missing extension(s).
            """
        )
        assert result is CheckState.FAILED

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU extensions
                     Unable to parse the output from 'lscpu' - unable to check
                     for the required CPU extensions: sse4_1, sse4_2, ssse3
                     All of these extensions must be installed.
            """
        )
        assert result is CheckState.ERROR

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- CPU extensions
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestHugepages(_CheckTestBase):
    """Tests for the hugepages check."""

    check_group = "xrd-vrouter"
    check_name = "Hugepages"
    files = ["/proc/meminfo"]

    def test_1_GB_hugepages(self, capsys):
        """Test the success case where 1 GiB hugepages are in use."""
        hugepages_data = "\n".join(
            [
                "HugePages_Total: 3",
                "Hugepagesize: 1 GB",
                "HugePages_Free: 3",
            ]
        )
        result, output = self.perform_check(
            capsys, read_effects=hugepages_data
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            PASS -- Hugepages (3 x 1GiB)
            """
        )
        assert result is CheckState.SUCCESS

    def test_2_MB_supported(self, capsys):
        """Test the case where only 2 MiB hugepages are supported and in use."""
        hugepages_data = "\n".join(
            [
                "HugePages_Total: 2000",
                "Hugepagesize: 2048 kB",
                "HugePages_Free: 2000",
            ]
        )
        result, output = self.perform_check(
            capsys, read_effects=hugepages_data
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            WARN -- Hugepages
                    2MiB hugepages are available, but only 1GiB hugepages are
                    supported for XRd deployment use cases.
            """
        )
        assert result is CheckState.WARNING

    def test_unaccepted_size(self, capsys):
        """Test the case where the hugepages size is not accepted."""
        hugepages_data = "\n".join(
            [
                "HugePages_Total: 1500",
                "Hugepagesize: 3 MB",
                "HugePages_Free: 1500",
            ]
        )
        result, output = self.perform_check(
            capsys, read_effects=hugepages_data
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Hugepages
                    3MiB hugepages are available, but XRd requires 1GiB hugepages.
            """
        )
        assert result is CheckState.FAILED

    def test_insufficient_memory_1_GB(self, capsys):
        """
        Test the case where the hugepages memory is not sufficient and 1G
        hugepages are being used.
        """
        hugepages_data = "\n".join(
            [
                "HugePages_Total: 512",
                "Hugepagesize: 1 GB",
                "HugePages_Free: 2",
            ]
        )
        result, output = self.perform_check(
            capsys, read_effects=hugepages_data
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Hugepages
                    Only 2.0GiB of hugepage memory available, but XRd
                    requires at least 3GiB.
            """
        )
        assert result is CheckState.FAILED

    def test_insufficient_memory_2_MB(self, capsys):
        """
        Test the case where the hugepages memory is not sufficient and 2M
        hugepages are being used.
        """
        hugepages_data = "\n".join(
            [
                "HugePages_Total: 512",
                "Hugepagesize: 2 MB",
                "HugePages_Free: 512",
            ]
        )
        result, output = self.perform_check(
            capsys, read_effects=hugepages_data
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Hugepages
                    2MiB hugepages are available, but only 1GiB hugepages are
                    supported for XRd deployment use cases.
                    Only 1.0GiB of hugepage memory available, but XRd
                    requires at least 3GiB.
            """
        )
        assert result is CheckState.FAILED

    def test_hugepages_disabled(self, capsys):
        """Test the case where hugepages are not enabled."""
        hugepages_data = "\n".join(
            [
                "HugePages_Total: 0",
                "Hugepagesize: 2 MB",
                "HugePages_Free: 0",
            ]
        )
        result, output = self.perform_check(
            capsys, read_effects=hugepages_data
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Hugepages
                    Hugepages are not enabled. These are required for XRd to function correctly.
                    To enable hugepages, see the instructions at:
                    https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt.
            """
        )
        assert result is CheckState.FAILED

    def test_mem_oserror(self, capsys):
        """Test an OS error being raised when trying to read from /proc/meminfo."""
        result, output = self.perform_check(capsys, read_effects=OSError)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Hugepages
                     Unable to parse the contents of /proc/meminfo - unable to check
                     whether hugepages are enabled with 1GiB (recommended)
                     or 2MiB hugepage size and at least 3GiB of available
                     hugepage memory.
            """
        )
        assert result is CheckState.ERROR

    def test_value_error(self, capsys):
        """Test a value error being raised."""
        result, output = self.perform_check(capsys, read_effects=ValueError)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Hugepages
                     Unable to parse the contents of /proc/meminfo - unable to check
                     whether hugepages are enabled with 1GiB (recommended)
                     or 2MiB hugepage size and at least 3GiB of available
                     hugepage memory.
            """
        )
        assert result is CheckState.ERROR

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, read_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Hugepages
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestGDPKernelDriver(_CheckTestBase):
    """Tests for the Interface kernel driver check."""

    check_group = "xrd-vrouter"
    check_name = "Interface kernel driver"

    cmds = [
        "lsmod | grep -q '^vfio_pci '",  # loaded
        "grep -q /vfio-pci.ko /lib/modules/*/modules.builtin",  # builtin
        "lsmod | grep -q '^igb_uio '",  # loaded
        "grep -q /igb_uio.ko /lib/modules/*/modules.builtin",  # builtin
        "grep -q /vfio-pci.ko /lib/modules/*/modules.*",  # installed
        "grep -q /igb_uio.ko /lib/modules/*/modules.*",  # installed
    ]

    def test_both_loaded(self, capsys):
        """Test the case where both PCI drivers are loaded."""
        # Command (grep -q) simply returns 0.
        result, output = self.perform_check(
            capsys, cmd_effects=["", None, "", None, None, None]
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            PASS -- Interface kernel driver
                    Loaded PCI drivers: vfio-pci, igb_uio
            """
        )
        assert result is CheckState.SUCCESS

    def test_both_builtin(self, capsys):
        """Test the case where both PCI drivers are builtin."""
        # Command (grep -q) simply returns 0.
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                subprocess.CalledProcessError(1, ""),
                "",
                subprocess.CalledProcessError(1, ""),
                "",
                None,
                None,
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            PASS -- Interface kernel driver
                    Loaded PCI drivers: vfio-pci, igb_uio
            """
        )
        assert result is CheckState.SUCCESS

    def test_both_installed(self, capsys):
        """Test the case where vfio-pci is installed but not loaded."""
        # Command (grep -q) simply returns 0.
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                subprocess.CalledProcessError(1, ""),
                subprocess.CalledProcessError(1, ""),
                subprocess.CalledProcessError(1, ""),
                subprocess.CalledProcessError(1, ""),
                "",
                "",
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- Interface kernel driver
                    None of the expected PCI drivers are loaded.
                    The following PCI drivers are installed but not loaded: vfio-pci, igb_uio.
                    Run 'modprobe <pci driver>' to load a driver.
            """
        )
        assert result is CheckState.FAILED

    def test_both_missing(self, capsys):
        """Test the case where vfio-pci is not loaded."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError,
                subprocess.SubprocessError,
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- Interface kernel driver
                    No PCI drivers are loaded or installed.
                    Must have either the vfio-pci or igb_uio kernel module loaded.
                    It may be possible to install using your distro's package manager.
            """
        )
        assert result is CheckState.FAILED

    def test_loaded_and_installed(self, capsys):
        """Test where vfio-pci is loaded and igb_uio is installed but not loaded."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                "",
                None,
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                None,
                "",
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            INFO -- Interface kernel driver
                    The following PCI drivers are installed but not loaded: igb_uio.
                    Loaded PCI drivers: vfio-pci.
                    Run 'modprobe <pci driver>' to load a driver.
            """
        )
        assert result is CheckState.NEUTRAL

    def test_installed_and_builtin(self, capsys):
        """Test where vfio-pci is installed but not loaded and igb_uio is builtin."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                "",
                "",
                None,
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            INFO -- Interface kernel driver
                    The following PCI drivers are installed but not loaded: vfio-pci.
                    Loaded PCI drivers: igb_uio.
                    Run 'modprobe <pci driver>' to load a driver.
            """
        )
        assert result is CheckState.NEUTRAL

    def test_missing_and_installed(self, capsys):
        """Test where vfio-pci is missing and igb_uio is installed."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                subprocess.SubprocessError(1, ""),
                "",
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- Interface kernel driver
                    None of the expected PCI drivers are loaded.
                    The following PCI drivers are installed but not loaded: igb_uio.
                    Run 'modprobe <pci driver>' to load a driver.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- Interface kernel driver
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestIOMMU(_CheckTestBase):
    """Tests for the IOMMU check."""

    check_group = "xrd-vrouter"
    check_name = "IOMMU"
    deps = ["Interface kernel driver"]
    cmds = [
        "lsmod | grep -q '^vfio_pci '",
        "grep -q /vfio-pci.ko /lib/modules/*/modules.builtin",
        "lsmod | grep -q '^igb_uio '",
        "grep -q /igb_uio.ko /lib/modules/*/modules.builtin",
        "lshw -businfo -c network",
    ]
    files = ["/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"]

    def test_success(self, capsys):
        """Test the success case."""
        lshw_output = """\
Bus info          Device      Class      Description
====================================================
pci@0000:00:00.0  device1     network    82540EM Gigabit Ethernet Controller
pci@0000:00:1f.2  device4     network    Ethernet interface
pci@0000:00:02.0  device3     network    82540EM Gigabit Ethernet Controller
pci@0000:00:01.0  device2     network    Ethernet interface
                  docker0     network    Ethernet interface


        """
        iommu_devices = [
            "0000:00:00.0",
            "0000:00:01.0",
            "0000:00:02.0",
            "0000:00:1f.0",
            "0000:00:1f.2",
            "0000:00:1f.3",
        ]
        with mock.patch("glob.glob", return_value=iommu_devices):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                    lshw_output,
                ],
                read_effects="N",
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            PASS -- IOMMU
                    IOMMU enabled for vfio-pci with the following PCI device(s):
                    device1 (0000:00:00.0), device2 (0000:00:01.0), device3 (0000:00:02.0),
                    device4 (0000:00:1f.2)
            """
        )
        assert result is CheckState.SUCCESS

    def test_no_iommu_devices(self, capsys):
        """Test the case where no devices are found."""
        lshw_output = """\
Bus info          Device      Class      Description
====================================================
pci@0000:00:02.0  enp0s2      network    82540EM Gigabit Ethernet Controller
pci@0000:00:1f.2  docker0     network    Ethernet interface
        """
        iommu_devices = ["0000:00:00.0", "0000:00:01.0"]
        with mock.patch("glob.glob", return_value=iommu_devices):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                    lshw_output,
                ],
                read_effects="N",
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- IOMMU
                    IOMMU enabled for vfio-pci, but no network PCI devices found.
            """
        )
        assert result is CheckState.WARNING

    def test_lshw_error(self, capsys):
        """Test the case where an error is hit when searching for network devices."""
        iommu_devices = [
            "0000:00:00.0",
            "0000:00:01.0",
            "0000:00:02.0",
            "0000:00:1f.0",
            "0000:00:1f.2",
            "0000:00:1f.3",
        ]
        with mock.patch("glob.glob", return_value=iommu_devices):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                ],
                read_effects="N",
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- IOMMU
                     The cmd 'lshw -businfo -c network' failed - unable to
                     determine the network devices on the host. IOMMU is enabled.
            """
        )
        assert result is CheckState.ERROR

    def test_no_net_devices(self, capsys):
        """Test the case where no network devices are found."""
        lshw_output = """\
Bus info          Device      Class      Description
====================================================
        """
        iommu_devices = [
            "0000:00:00.0",
            "0000:00:01.0",
            "0000:00:02.0",
            "0000:00:1f.0",
            "0000:00:1f.2",
            "0000:00:1f.3",
        ]
        with mock.patch("glob.glob", return_value=iommu_devices):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                    lshw_output,
                ],
                read_effects="N",
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- IOMMU (no PCI network devices found)
            """
        )
        assert result is CheckState.WARNING

    def test_iommu_directory_check_error(self, capsys):
        """Test the case where the IOMMU check throws an error."""
        with mock.patch("glob.glob", side_effect=Exception):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                ],
                read_effects="N",
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- IOMMU
                     Unable to check if IOMMU is enabled by listing /sys/class/iommu/*/devices/*.
                     IOMMU is recommended for security when using the vfio-pci kernel driver.
            """
        )
        assert result is CheckState.ERROR

    def test_iommu_not_enabled(self, capsys):
        """Test the case where IOMMU is not enabled."""
        with mock.patch("glob.glob", return_value=[]):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                ],
                read_effects="N",
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- IOMMU
                    The kernel module vfio-pci cannot be used, as IOMMU is not enabled.
                    IOMMU is recommended for security when using the vfio-pci kernel driver.
            """
        )
        assert result is CheckState.WARNING

    def test_no_iommu_mode(self, capsys):
        """Test the case where vfio-pci is set up in no-IOMMU mode."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                "",
                None,
                subprocess.SubprocessError,
                subprocess.SubprocessError,
            ],
            read_effects="Y",
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            WARN -- IOMMU
                    vfio-pci is set up in no-IOMMU mode, but IOMMU is recommended for security.
            """
        )
        assert result is CheckState.WARNING

    def test_no_iommu_unconfigurable(self, capsys):
        """
        Test the case where the check for vfio-pci 'no-IOMMU' mode throws an
        OS error because IOMMU is unconfigurable - should result in success.
        """
        lshw_output = """\
Bus info          Device      Class      Description
====================================================
pci@0000:00:00.0  device1     network    82540EM Gigabit Ethernet Controller
pci@0000:00:1f.2  device4     network    Ethernet interface
pci@0000:00:02.0  device3     network    82540EM Gigabit Ethernet Controller
pci@0000:00:01.0  device2     network    Ethernet interface
                  docker0     network    Ethernet interface


        """
        iommu_devices = [
            "0000:00:00.0",
            "0000:00:01.0",
            "0000:00:02.0",
            "0000:00:1f.0",
            "0000:00:1f.2",
            "0000:00:1f.3",
        ]
        with mock.patch("glob.glob", return_value=iommu_devices):
            result, output = self.perform_check(
                capsys,
                cmd_effects=[
                    "",
                    None,
                    subprocess.SubprocessError,
                    subprocess.SubprocessError,
                    lshw_output,
                ],
                read_effects=OSError,
            )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            PASS -- IOMMU
                    IOMMU enabled for vfio-pci with the following PCI device(s):
                    device1 (0000:00:00.0), device2 (0000:00:01.0), device3 (0000:00:02.0),
                    device4 (0000:00:1f.2)
            """
        )
        assert result is CheckState.SUCCESS

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                "",
                None,
                subprocess.SubprocessError,
                subprocess.SubprocessError,
            ],
            read_effects=Exception("test exception"),
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- IOMMU
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR

    def test_failed_dependency(self, capsys):
        """Test a dependency failure."""
        result, output = self.perform_check(capsys, failed_deps=self.deps)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            SKIP -- IOMMU
                    Skipped due to failed checks: Interface kernel driver
            """
        )
        assert result is CheckState.SKIPPED

    def test_vfio_pci_not_enabled(self, capsys):
        """Test for when vfio-pci is not enabled."""
        result, output = self.perform_check(
            capsys,
            cmd_effects=[
                subprocess.SubprocessError,
                subprocess.SubprocessError,
            ],
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            INFO -- IOMMU (vfio-pci driver unavailable)
            """
        )
        assert result is CheckState.NEUTRAL

    def test_warn_igb_uio_enabled(self, capsys):
        """
        Test a failure that would result in a WARN result, but with igb_uio
        enabled is just INFO.
        """
        result, output = self.perform_check(
            capsys, cmd_effects=["", None, "", None], read_effects="Y"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            INFO -- IOMMU
                    vfio-pci is set up in no-IOMMU mode, but IOMMU is recommended for security.
            """
        )
        assert result is CheckState.NEUTRAL


class TestSharedMemPageMaxSize(_CheckTestBase):
    """Tests for the shared memory pages maximum size check."""

    check_group = "xrd-vrouter"
    check_name = "Shared memory pages max size"
    files = ["/proc/sys/kernel/shmmax"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, read_effects="2147483648")
        assert (
            textwrap.dedent(output)
            == "PASS -- Shared memory pages max size (2.0 GiB)\n"
        )
        assert result is CheckState.SUCCESS

    def test_oserror(self, capsys):
        """Test the OS error case."""
        result, output = self.perform_check(capsys, read_effects=OSError)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Shared memory pages max size
                     Unable to read the contents of /proc/sys/kernel/shmmax - unable to
                     determine the maximum size of shared memory pages.
                     At least 2 GiB are required.
            """
        )
        assert result is CheckState.ERROR

    def test_failure(self, capsys):
        """Test the OS error case."""
        result, output = self.perform_check(capsys, read_effects="1073741824")
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Shared memory pages max size
                    The maximum size of shared memory pages is 1.0 GiB,
                    but at least 2 GiB are required.
            """
        )
        assert result is CheckState.FAILED

    def test_exception(self, capsys):
        """Test the Exception case."""
        result, output = self.perform_check(
            capsys, read_effects="not an integer"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Shared memory pages max size
                     Unable to parse the contents of /proc/sys/kernel/shmmax - unable to
                     determine the maximum size of shared memory pages.
                     At least 2 GiB are required.
            """
        )
        assert result is CheckState.ERROR

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, read_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Shared memory pages max size
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


# -------------------------------------
# Docker checks tests
# -------------------------------------


class TestDockerClient(_CheckTestBase):
    """Tests for the docker client version check."""

    check_group = "docker"
    check_name = "Docker client"
    cmds = ["docker --version"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(
            capsys, cmd_effects="Docker version 18.0.4"
        )
        assert (
            textwrap.dedent(output)
            == "PASS -- Docker client (version 18.0.4)\n"
        )
        assert result is CheckState.SUCCESS

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Docker client
                    Docker client not correctly installed on the host (checked with
                    'docker --version').
                    See installation instructions at https://docs.docker.com/engine/install/.
                    At least version 18.0 is required for XRd.
            """
        )
        assert result is CheckState.FAILED

    def test_no_version_match(self, capsys):
        """Test failure to match the version in the output."""
        result, output = self.perform_check(
            capsys, cmd_effects="unexpected output"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Docker client
                     Unable to parse Docker client version from 'docker --version'.
                     At least version 18.0 is required for XRd.
            """
        )
        assert result is CheckState.ERROR

    def test_old_version(self, capsys):
        """Test the version being too old."""
        result, output = self.perform_check(
            capsys, cmd_effects="Docker version 17.11"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Docker client
                    Docker version must be at least 18.0, current client version is 17.11.
                    See installation instructions at https://docs.docker.com/engine/install/.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Docker client
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestDockerDaemon(_CheckTestBase):
    """Tests for the docker daemon check."""

    check_group = "docker"
    check_name = "Docker daemon"
    cmds = ["docker version -f '{{json .Server.Version}}'"]
    deps = ["Docker client"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, cmd_effects='"18.0.4"')
        assert (
            textwrap.dedent(output)
            == "PASS -- Docker daemon (running, version 18.0.4)\n"
        )
        assert result is CheckState.SUCCESS

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Docker daemon
                    Unable to connect to the Docker daemon (checked with
                    "docker version -f '{{json .Server.Version}}'").
                    This could be because it isn't running, or due to insufficient permissions.
                    See installation instructions at https://docs.docker.com/engine/install/.
            """
        )
        assert result is CheckState.FAILED

    def test_no_version_match(self, capsys):
        """Test failure to match the version in the output."""
        result, output = self.perform_check(
            capsys, cmd_effects="unexpected output"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Docker daemon
                     Unable to parse Docker server version from
                     "docker version -f '{{json .Server.Version}}'".
                     At least version 18.0 is required for XRd.
            """
        )
        assert result is CheckState.ERROR

    def test_old_version(self, capsys):
        """Test the version being too old."""
        result, output = self.perform_check(capsys, cmd_effects='"17.11"')
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Docker daemon
                    Docker version must be at least 18.0, current server version is 17.11.
                    See installation instructions at https://docs.docker.com/engine/install/.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Docker daemon
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR

    def test_failed_dependency(self, capsys):
        """Test a dependency failure."""
        result, output = self.perform_check(capsys, failed_deps=self.deps)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            SKIP -- Docker daemon
                    Skipped due to failed checks: Docker client
            """
        )
        assert result is CheckState.SKIPPED


class TestDtypeSupport(_CheckTestBase):
    """Tests for the Docker d-type filesystem support check."""

    check_group = "docker"
    check_name = "Docker supports d_type"
    cmds = ["docker info"]
    deps = ["Docker daemon"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(
            capsys, cmd_effects="Supports d_type: true"
        )
        assert textwrap.dedent(output) == "PASS -- Docker supports d_type\n"
        assert result is CheckState.SUCCESS

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Docker supports d_type
                     'docker info' command failed.
                     Unable to check filesystem support for d_type (directory entry type).
                     This is required for XRd to avoid issues with creating and deleting files.
            """
        )
        assert result is CheckState.ERROR

    def test_no_dtype_match(self, capsys):
        """Test failure to match on d_type support in the output."""
        result, output = self.perform_check(
            capsys, cmd_effects="unexpected output"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- Docker supports d_type
                    Docker is using a backing filesystem that does not support d_type
                    (directory entry type).
                    This is required for XRd to avoid issues with creating and deleting files.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- Docker supports d_type
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR

    def test_failed_dependency(self, capsys):
        """Test a dependency failure."""
        result, output = self.perform_check(capsys, failed_deps=self.deps)
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            SKIP -- Docker supports d_type
                    Skipped due to failed checks: Docker daemon
            """
        )
        assert result is CheckState.SKIPPED


# -------------------------------------
# XR compose checks tests
# -------------------------------------


class TestDockerCompose(_CheckTestBase):
    """Tests for the docker-compose check."""

    check_group = "xr-compose"
    check_name = "docker-compose"
    cmds = ["docker-compose --version"]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(
            capsys, cmd_effects="docker-compose version 1.18.0"
        )
        assert (
            textwrap.dedent(output)
            == "PASS -- docker-compose (version 1.18.0)\n"
        )
        assert result is CheckState.SUCCESS

    def test_subproc_error(self, capsys):
        """Test a subprocess error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=subprocess.SubprocessError
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- docker-compose
                    Docker Compose not found (checked with 'docker-compose --version').
                    Launching XRd topologies with xr-compose requires docker-compose.
                    See installation instructions at https://docs.docker.com/compose/install/.
            """
        )
        assert result is CheckState.FAILED

    def test_no_version_match(self, capsys):
        """Test failure to match the version in the output."""
        result, output = self.perform_check(
            capsys, cmd_effects="unexpected output"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- docker-compose
                     Unable to parse Docker Compose version, at least version 1.18 is required.
            """
        )
        assert result is CheckState.ERROR

    def test_old_version(self, capsys):
        """Test the version being too old."""
        result, output = self.perform_check(
            capsys, cmd_effects="docker-compose version 1.17.10"
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            FAIL -- docker-compose
                    Docker Compose version must be at least 1.18, current version is 1.17.10.
                    See installation instructions at https://docs.docker.com/compose/install/.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        result, output = self.perform_check(
            capsys, cmd_effects=Exception("test exception")
        )
        assert textwrap.dedent(output) == textwrap.dedent(
            """\
            ERROR -- docker-compose
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestPyYAML(_CheckTestBase):
    """Tests for the yaml import check."""

    check_group = "xr-compose"
    check_name = "PyYAML"

    def test_success(self, capsys):
        """Test the success case."""
        with mock.patch("builtins.__import__"):
            result, output = self.perform_check(capsys)
        assert textwrap.dedent(output) == f"PASS -- PyYAML (installed)\n"
        assert result is CheckState.SUCCESS

    def test_unavailable(self, capsys):
        """Test yaml not being available."""
        with mock.patch("builtins.__import__", side_effect=ImportError):
            result, output = self.perform_check(capsys)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- PyYAML
                    PyYAML Python package not installed - required for running xr-compose.
                    Install with 'python3 -m pip install pyyaml'.
            """
        )
        assert result is CheckState.FAILED

    def test_unexpected_error(self, capsys):
        """Test unexpected error being raised."""
        with mock.patch(
            "builtins.__import__", side_effect=Exception("test exception")
        ):
            result, output = self.perform_check(capsys)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- PyYAML
                     Unexpected error: test exception
            """
        )
        assert result is CheckState.ERROR


class TestBridgeIptables(_CheckTestBase):
    """Tests for the bridge iptables check."""

    check_group = "xr-compose"
    check_name = "Bridge iptables"
    files = [
        "/proc/sys/net/bridge/bridge-nf-call-iptables",
        "/proc/sys/net/bridge/bridge-nf-call-ip6tables",
    ]

    def test_success(self, capsys):
        """Test the success case."""
        result, output = self.perform_check(capsys, read_effects=["0", "0"])
        assert (
            textwrap.dedent(output) == "PASS -- Bridge iptables (disabled)\n"
        )
        assert result is CheckState.SUCCESS

    def test_not_disabled(self, capsys):
        """Test bridge iptables not being disabled."""
        result, output = self.perform_check(capsys, read_effects=["0", "1"])
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            FAIL -- Bridge iptables
                    For xr-compose to be able to use Docker bridges, bridge IP tables must
                    be disabled. Note that there may be security considerations associated
                    with doing so.
                    Bridge IP tables can be disabled by setting the kernel parameters
                    net.bridge.bridge-nf-call-iptables and net.bridge.bridge-nf-call-ip6tables
                    to 0. These can be modified by adding 'net.bridge.bridge-nf-call-iptables=0'
                    and 'net.bridge.bridge-nf-call-ip6tables=0' to /etc/sysctl.conf or in a
                    dedicated conf file under /etc/sysctl.d/.
                    For a temporary fix, run:
                      sysctl -w net.bridge.bridge-nf-call-iptables=0
                      sysctl -w net.bridge.bridge-nf-call-ip6tables=0
            """
        )
        assert result is CheckState.FAILED

    def test_error(self, capsys):
        """Test error being raised."""
        result, output = self.perform_check(capsys, read_effects=Exception)
        assert textwrap.dedent(output) == textwrap.dedent(
            f"""\
            ERROR -- Bridge iptables
                     Failed to read iptables settings under /proc/sys/net/bridge/.
                     For xr-compose to be able to use Docker bridges, bridge IP tables must
                     be disabled. Note that there may be security considerations associated
                     with doing so.
                     Bridge IP tables can be disabled by setting the kernel parameters
                     net.bridge.bridge-nf-call-iptables and net.bridge.bridge-nf-call-ip6tables
                     to 0. These can be modified by adding 'net.bridge.bridge-nf-call-iptables=0'
                     and 'net.bridge.bridge-nf-call-ip6tables=0' to /etc/sysctl.conf or in a
                     dedicated conf file under /etc/sysctl.d/.
                     For a temporary fix, run:
                       sysctl -w net.bridge.bridge-nf-call-iptables=0
                       sysctl -w net.bridge.bridge-nf-call-ip6tables=0
            """
        )
        assert result is CheckState.ERROR

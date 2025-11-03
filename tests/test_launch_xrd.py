# Copyright 2021-2025 Cisco Systems Inc.
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
UT for launch-xrd script, using pytest.
"""

import shlex
import subprocess
from typing import Dict, List, Optional

from .utils import REPO_ROOT_DIR


LAUNCH_XRD_SCRIPT = REPO_ROOT_DIR / "scripts" / "launch-xrd"

# -----------------------------------------------------------------------------
# Exceptions and Helpers
# -----------------------------------------------------------------------------


class CmdFailure(Exception):
    """
    Class to indicate that launch-xrd has an error with the passed command.

    """


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------


class TestCLIArguments:
    """
    Test that the CLI arguments passed along with `launch-xrd` are correctly
    parsed into docker-specific arguments.

    """

    default_caps: Dict[str, List[str]] = {
        "--cap-drop": ["all"],
        "--cap-add": [
            "AUDIT_WRITE",
            "CHOWN",
            "DAC_OVERRIDE",
            "FOWNER",
            "FSETID",
            "KILL",
            "MKNOD",
            "NET_BIND_SERVICE",
            "NET_RAW",
            "SETFCAP",
            "SETGID",
            "SETUID",
            "SETPCAP",
            "SYS_CHROOT",
            "IPC_LOCK",
            "NET_ADMIN",
            "SYS_ADMIN",
            "SYSLOG",
            "SYS_NICE",
            "SYS_PTRACE",
            "SYS_RESOURCE",
        ],
    }

    default_devices: Dict[str, List[str]] = {
        "--device": ["/dev/fuse", "/dev/net/tun"]
    }
    default_env: Dict[str, List[str]] = {
        "--env": ["XR_MGMT_INTERFACES=linux:eth0,chksum"]
    }
    default_sec_opts: Dict[str, List[str]] = {
        "--security-opt": ["label=disable", "apparmor=unconfined"]
    }
    default_img: str = "dummy_image"

    @classmethod
    def run_dry_launch_xrd(
        cls, cli_args: Optional[List[str]] = None
    ) -> List[str]:
        """
        Call `launch-xrd` under dry-run mode, and return a list of the parsed
        arguments.

        """
        if not cli_args:
            cli_args = []

        # Build the command: launch-xrd --dry-run <cli_args>.
        cmd = [
            str(LAUNCH_XRD_SCRIPT),
            "--platform",
            "xrd-control-plane",  # Just use control plane as the default plat.
            cls.default_img,
            "--dry-run",
        ] + cli_args

        try:
            # Run the command and capture output
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as exc:
            # The actual CalledProcessError isn't usefule at all- it just
            # indicates that the process failed. Re-raising this as a
            # CmdFailure with the stderr of the original exception provides a
            # more helpful clue.
            raise CmdFailure(f"Command failed: {exc.stderr}") from exc

        # The dry-run output is the command that would be executed
        # Parse it back into a list of arguments using shlex.
        return shlex.split(result.stdout.strip())

    def compare_output_to_expected(
        self,
        actual_output: List[str],
        expected_caps: Optional[Dict[str, List[str]]] = default_caps,
        expected_devices: Optional[Dict[str, List[str]]] = default_devices,
        expected_env: Optional[Dict[str, List[str]]] = default_env,
        expected_security_opts: Optional[
            Dict[str, List[str]]
        ] = default_sec_opts,
        expected_use_rm: bool = True,
        expected_privileged: bool = False,
    ) -> None:
        actual_caps: Dict[str, List[str]] = {"--cap-drop": [], "--cap-add": []}
        actual_devices: List[str] = []
        actual_env: List[str] = []
        actual_sec_opts: List[str] = []
        actual_use_rm: bool = False
        actual_priv: bool = False

        append_next: Dict[str, int] = {
            "--cap-drop": 0,
            "--cap-add": 0,
            "--device": 0,
            "--env": 0,
            "--security-opt": 0,
        }

        for parsed_arg in actual_output:
            if parsed_arg in append_next:
                # Indicate that the next argument is one that we are interested
                # in.
                append_next[parsed_arg] = 1
            else:
                # This means that the current entry in the list is not a cli
                # option we are interested in- it may be a parsed arg we need
                # to append.
                if append_next["--cap-drop"] == 1:
                    actual_caps["--cap-drop"].append(parsed_arg)
                    append_next["--cap-drop"] = 0
                elif append_next["--cap-add"] == 1:
                    actual_caps["--cap-add"].append(parsed_arg)
                    append_next["--cap-add"] = 0
                elif append_next["--device"] == 1:
                    actual_devices.append(parsed_arg)
                    append_next["--device"] = 0
                elif append_next["--env"] == 1:
                    actual_env.append(parsed_arg)
                    append_next["--env"] = 0
                elif append_next["--security-opt"] == 1:
                    actual_sec_opts.append(parsed_arg)
                    append_next["--security-opt"] = 0
                else:
                    # These could be some other flags we are interested in, or
                    # some details we can ignore for the purpose of the tests.
                    if parsed_arg == "--rm":
                        actual_use_rm = True
                    elif parsed_arg == "--privileged":
                        actual_priv = True

        # After we are done collecting all the values, verify that the actual
        # and expected are equal.
        if not expected_caps:
            expected_caps = {"--cap-drop": [], "--cap-add": []}
        if not expected_devices:
            expected_devices = {"--device": []}
        if not expected_env:
            expected_env = {"--env": []}
        if not expected_security_opts:
            expected_security_opts = {"--security-opt": []}

        assert (
            actual_caps == expected_caps
        ), "Difference between actual and expected caps."
        assert {
            "--device": actual_devices
        } == expected_devices, (
            "Difference between actual and expected devices."
        )
        assert {
            "--env": actual_env
        } == expected_env, "Difference between actual and expected envs."
        assert {
            "--security-opt": actual_sec_opts
        } == expected_security_opts, (
            "Difference between actual and expected security options."
        )
        assert (
            actual_use_rm == expected_use_rm
        ), "Difference in the presence of `--rm` between the actual versus expected outputs."
        assert (
            actual_priv == expected_privileged
        ), "Difference in the expected privilege level of the container."

    def test_default(self) -> None:
        """
        Call `launch-xrd` without specifying any of the optional CLI
        arguments.

        """
        # Run the script with no optional arguments.
        default_output = self.run_dry_launch_xrd()
        # Compare the actual output the the defaul expected outputs.
        self.compare_output_to_expected(default_output)

    def test_privileged_mode(self) -> None:
        """
        Call `launch-xrd` with privileged mode specified.

        """
        # Run the script with the privileged argument.
        priv_output = self.run_dry_launch_xrd(["--privileged"])
        # Compare the actual output the the defaul expected outputs. Privileged
        # mode should overrride any caps, devices, and security options in this
        # case.
        self.compare_output_to_expected(
            priv_output,
            expected_caps=None,
            expected_devices=None,
            expected_security_opts=None,
            expected_privileged=True,
        )

    def test_apparmor_enabled(self) -> None:
        """
        Call `launch-xrd` while indicating that AppArmor is enabled for the
        host.

        """
        # Run the script and indicate that apparmor is enabled.
        aa_enabled_output = self.run_dry_launch_xrd(["--apparmor-enabled"])
        # Compare the actual output the the defaul expected outputs. The
        # prescence of apparmor-enabled should force the use of the
        # xrd-unconfined profile.
        self.compare_output_to_expected(
            aa_enabled_output,
            expected_security_opts={
                "--security-opt": ["label=disable", "apparmor=xrd-unconfined"]
            },
        )

    def test_privileged_apparmor(self) -> None:
        """
        Call `launch-xrd` with both the privileged and apparmor_enabled
        arguments passed.

        """
        # Run the script with the privileged argument and indicate that
        # apparmor is enabled.
        priv_output = self.run_dry_launch_xrd(
            ["--privileged", "--apparmor-enabled"]
        )
        # Compare the actual output the the defaul expected outputs. Privileged
        # mode should overrride any caps, devices, and security options, but
        # the prescence of apparmor-enabled should force the use of the
        # xrd-unconfined profile.
        self.compare_output_to_expected(
            priv_output,
            expected_caps=None,
            expected_devices=None,
            expected_security_opts={
                "--security-opt": ["apparmor=xrd-unconfined"]
            },
            expected_privileged=True,
        )

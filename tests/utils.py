# Copyright 2022 Cisco Systems Inc.
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

__all__ = (
    "REPO_ROOT_DIR",
    "TEST_DIR",
    "import_path",
)

import importlib.machinery
import importlib.util
import os.path
import pathlib
import sys
import types


TEST_DIR = pathlib.Path(__file__).parent
REPO_ROOT_DIR = TEST_DIR.parent


def import_path(path: str) -> types.ModuleType:
    """
    Import a Python file from a path.

    This is required for scripts that can't be imported normally due to hyphens
    and lack of .py extension.
    """
    path = str(path)
    module_name = os.path.basename(path).replace("-", "_")
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_loader(
        module_name, importlib.machinery.SourceFileLoader(module_name, path)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[module_name] = module
    return module

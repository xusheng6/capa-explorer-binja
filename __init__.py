# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
capa explorer for Binary Ninja -- plugin entry point.

Binary Ninja loads this package (the plugin manager clones the repo into the
user plugins directory and imports it, running this ``__init__``). The UI lives
here; the capabilities engine and the Binary Ninja feature extractor come from
the separately pip-installed ``flare-capa`` package (see requirements.txt), so
this plugin is intentionally decoupled from capa's release cycle.
"""

import sys
import logging

import binaryninja

logger = logging.getLogger(__name__)


def _capa_import_error_message(error: Exception) -> str:
    """explain a failure to import flare-capa (the most common install issue)"""
    base = (
        "The 'flare-capa' package is not usable in Binary Ninja's Python environment. "
        f"Binary Ninja is running Python {sys.version_info.major}.{sys.version_info.minor} "
        f"at {sys.executable}."
    )

    if isinstance(error, ModuleNotFoundError):
        missing = error.name or str(error)
        # these are compiled extension modules; a missing one almost always
        # means flare-capa was installed against a different Python ABI.
        if missing in {
            "msgspec._core",
            "pydantic_core._pydantic_core",
            "msgpack._cmsgpack",
            "_yaml",
        }:
            return (
                f"{base} Missing compiled module '{missing}' -- flare-capa was likely "
                "installed with a different Python version/ABI than Binary Ninja. "
                "Reinstall flare-capa using the interpreter Binary Ninja uses "
                "(Settings > Python interpreter), not the system python."
            )
        return (
            f"{base} Missing module '{missing}'. Install flare-capa into Binary "
            "Ninja's Python environment."
        )

    return f"{base} Import failed: {type(error).__name__}: {error}"


def _register():
    # delay these imports until registration time so a broken/missing
    # dependency surfaces as a clear log message rather than a silent
    # import-time failure during Binary Ninja startup.
    from . import settings
    from binaryninjaui import Sidebar
    from .form import CapaExplorerSidebarWidgetType
    from .context_menu import register_context_menu

    settings.register()
    Sidebar.addSidebarWidgetType(CapaExplorerSidebarWidgetType())
    register_context_menu()
    binaryninja.log_info("capa explorer loaded; open it from the sidebar.")


try:
    _register()
except ImportError as e:
    # almost always: flare-capa missing or built for the wrong Python/ABI
    binaryninja.log_error(
        f"capa explorer failed to load. {_capa_import_error_message(e)}"
    )
    logger.exception("capa explorer failed to load")
except Exception as e:  # noqa: BLE001 - never break Binary Ninja startup
    binaryninja.log_error(f"capa explorer failed to load: {e}")
    logger.exception("capa explorer failed to load")

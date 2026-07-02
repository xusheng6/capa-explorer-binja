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

import logging

import binaryninja

logger = logging.getLogger(__name__)


def _register():
    # delay these imports until registration time so a broken/missing
    # dependency surfaces as a clear log message rather than a silent
    # import-time failure during Binary Ninja startup.
    from . import settings
    from binaryninjaui import Sidebar
    from .form import CapaExplorerSidebarWidgetType

    settings.register()
    Sidebar.addSidebarWidgetType(CapaExplorerSidebarWidgetType())
    binaryninja.log_info("capa explorer loaded; open it from the sidebar.")


try:
    _register()
except Exception as e:  # noqa: BLE001 - we never want to break Binary Ninja startup
    binaryninja.log_error(
        f"capa explorer failed to load: {e}. "
        "Ensure 'flare-capa' is installed for the Python interpreter Binary Ninja uses."
    )
    logger.exception("capa explorer failed to load")

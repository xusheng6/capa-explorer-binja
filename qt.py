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
Qt compatibility shim for the capa Binary Ninja plugin.

Binary Ninja ships its own copy of Qt and exposes which major version is in use
via ``binaryninjaui.qt_major_version``. Recent Binary Ninja builds use PySide6;
older builds use PySide2. We follow the same detection idiom that the bundled
Binary Ninja example plugins (e.g. hashdb) use so we import the matching
bindings.
"""

import binaryninjaui

if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6 import QtGui, QtCore, QtWidgets
    from PySide6.QtGui import QAction

    Signal = QtCore.Signal
else:
    from PySide2 import QtGui, QtCore, QtWidgets  # type: ignore[no-redef]
    from PySide2.QtWidgets import QAction  # type: ignore[no-redef]

    Signal = QtCore.Signal

Qt = QtCore.Qt


def qt_get_item_flag_tristate():
    """
    Return the tristate item flag in a way that works on both Qt5 and Qt6.

    Qt6 (PySide6) removed ``Qt.ItemIsTristate`` in favor of
    ``Qt.ItemIsAutoTristate``; Qt5 (PySide2) only has the former.
    """
    if hasattr(Qt, "ItemIsAutoTristate"):
        return Qt.ItemIsAutoTristate
    if hasattr(Qt, "ItemFlag") and hasattr(Qt.ItemFlag, "ItemIsAutoTristate"):
        return Qt.ItemFlag.ItemIsAutoTristate
    return Qt.ItemIsTristate


__all__ = [
    "qt_get_item_flag_tristate",
    "Signal",
    "QAction",
    "QtGui",
    "QtCore",
    "QtWidgets",
    "Qt",
]

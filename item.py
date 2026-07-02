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
Tree items backing the capa results model.

Ported from capa.ida.plugin.item. The item classes are mostly pure data; the
only disassembler coupling is that a few leaf items render disassembly/bytes/
names at construction time, so those take a BinaryView and go through
capa.binja.plugin.helpers instead of calling idaapi/idc directly.
"""

import codecs
from typing import Iterator, Optional

import binaryninja

from . import helpers
from capa.features.address import Address, FileOffsetAddress, AbsoluteVirtualAddress
from .qt import QtCore, qt_get_item_flag_tristate


def info_to_name(display):
    """extract root value from display name

    e.g. function(my_function) => my_function
    """
    try:
        return display.split("(")[1].rstrip(")")
    except IndexError:
        return ""


def ea_to_hex(ea):
    """convert effective address (ea) to hex for display"""
    return f"{hex(ea)}"


class CapaExplorerDataItem:
    """store data for CapaExplorerDataModel"""

    def __init__(
        self, parent: Optional["CapaExplorerDataItem"], data: list[str], can_check=True
    ):
        """initialize item"""
        self.pred = parent
        self._data = data
        self._children: list[CapaExplorerDataItem] = []
        self._checked = False
        self._can_check = can_check

        # default state for item
        self.flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

        if self._can_check:
            self.flags = (
                self.flags | QtCore.Qt.ItemIsUserCheckable | qt_get_item_flag_tristate()
            )

        if self.pred:
            self.pred.appendChild(self)

    def setIsEditable(self, isEditable=False):
        """modify item editable flags"""
        if isEditable:
            self.flags |= QtCore.Qt.ItemIsEditable
        else:
            self.flags &= ~QtCore.Qt.ItemIsEditable

    def setChecked(self, checked):
        """set item as checked"""
        self._checked = checked

    def canCheck(self):
        return self._can_check

    def isChecked(self):
        """get item is checked"""
        return self._checked

    def appendChild(self, item: "CapaExplorerDataItem"):
        """add a new child to specified item"""
        self._children.append(item)

    def child(self, row: int) -> "CapaExplorerDataItem":
        """get child row"""
        return self._children[row]

    def childCount(self) -> int:
        """get child count"""
        return len(self._children)

    def columnCount(self) -> int:
        """get column count"""
        return len(self._data)

    def data(self, column: int) -> Optional[str]:
        """get data at column"""
        try:
            return self._data[column]
        except IndexError:
            return None

    def parent(self) -> Optional["CapaExplorerDataItem"]:
        """get parent"""
        return self.pred

    def row(self) -> int:
        """get row location"""
        if self.pred:
            return self.pred._children.index(self)
        return 0

    def setData(self, column: int, value: str):
        """set data in column"""
        self._data[column] = value

    def children(self) -> Iterator["CapaExplorerDataItem"]:
        """yield children"""
        yield from self._children

    def removeChildren(self):
        """remove children"""
        del self._children[:]

    def __str__(self):
        """get string representation of columns, used for copy-n-paste operations"""
        return " ".join([data for data in self._data if data])

    @property
    def info(self):
        """return data stored in information column"""
        return self._data[0]

    @property
    def location(self) -> Optional[int]:
        """return data stored in location column"""
        try:
            # address stored as str, convert to int before return
            return int(self._data[1], 16)
        except ValueError:
            return None

    @property
    def details(self):
        """return data stored in details column"""
        return self._data[2]


class CapaExplorerRuleItem(CapaExplorerDataItem):
    """store data for rule result"""

    fmt = "%s (%d matches)"

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        name: str,
        namespace: str,
        count: int,
        source: str,
        can_check=True,
    ):
        """initialize item"""
        display = self.fmt % (name, count) if count > 1 else name
        super().__init__(parent, [display, "", namespace], can_check)
        self._source = source

    @property
    def source(self):
        """return rule source to display (tooltip)"""
        return self._source


class CapaExplorerRuleMatchItem(CapaExplorerDataItem):
    """store data for rule match"""

    def __init__(self, parent: CapaExplorerDataItem, display: str, source=""):
        """initialize item"""
        super().__init__(parent, [display, "", ""])
        self._source = source

    @property
    def source(self):
        """return rule contents for display"""
        return self._source


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    """store data for function match"""

    fmt = "function(%s)"

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        bv: binaryninja.BinaryView,
        location: Address,
        can_check=True,
    ):
        """initialize item"""
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        super().__init__(
            parent,
            [self.fmt % helpers.get_function_name(bv, ea), ea_to_hex(ea), ""],
            can_check,
        )

    @property
    def info(self):
        """return function name"""
        info = super().info
        display = info_to_name(info)
        return display if display else info

    @info.setter
    def info(self, display):
        """set function name; called when user renames a function in the UI"""
        self._data[0] = self.fmt % display


class CapaExplorerSubscopeItem(CapaExplorerDataItem):
    """store data for subscope match"""

    fmt = "subscope(%s)"

    def __init__(self, parent: CapaExplorerDataItem, scope):
        """initialize item"""
        super().__init__(parent, [self.fmt % scope, "", ""])


class CapaExplorerBlockItem(CapaExplorerDataItem):
    """store data for basic block match"""

    fmt = "basic block(loc_%08X)"

    def __init__(self, parent: CapaExplorerDataItem, location: Address):
        """initialize item"""
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        super().__init__(parent, [self.fmt % ea, ea_to_hex(ea), ""])


class CapaExplorerInstructionItem(CapaExplorerBlockItem):
    """store data for instruction match"""

    fmt = "instruction(loc_%08X)"


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    """store data for default match e.g. statement (and, or)"""

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        display: str,
        details: str = "",
        location: Optional[Address] = None,
    ):
        """initialize item"""
        ea = None
        if location:
            assert isinstance(location, AbsoluteVirtualAddress)
            ea = int(location)

        super().__init__(
            parent, [display, ea_to_hex(ea) if ea is not None else "", details]
        )


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    """store data for feature match"""

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        display: str,
        location: Optional[Address] = None,
        details: str = "",
    ):
        """initialize item"""
        if location:
            assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
            ea = int(location)
            super().__init__(parent, [display, ea_to_hex(ea), details])
        else:
            super().__init__(parent, [display, "", details])


class CapaExplorerInstructionViewItem(CapaExplorerFeatureItem):
    """store data for instruction match; details show the disassembly line"""

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        bv: binaryninja.BinaryView,
        display: str,
        location: Address,
    ):
        """initialize item"""
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        details = helpers.get_disasm_line(bv, ea)
        super().__init__(parent, display, location=location, details=details)


class CapaExplorerByteViewItem(CapaExplorerFeatureItem):
    """store data for byte match; details show a hex byte preview"""

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        bv: binaryninja.BinaryView,
        display: str,
        location: Address,
    ):
        """initialize item"""
        assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
        ea = int(location)

        byte_snap = helpers.get_bytes(bv, ea, 32)

        details = ""
        if byte_snap:
            byte_snap = codecs.encode(byte_snap, "hex").upper()
            details = " ".join(
                [byte_snap[i : i + 2].decode() for i in range(0, len(byte_snap), 2)]
            )

        super().__init__(parent, display, location=location, details=details)


class CapaExplorerStringViewItem(CapaExplorerFeatureItem):
    """store data for string match"""

    def __init__(
        self, parent: CapaExplorerDataItem, display: str, location: Address, value: str
    ):
        """initialize item"""
        assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
        super().__init__(parent, display, location=location, details=value)

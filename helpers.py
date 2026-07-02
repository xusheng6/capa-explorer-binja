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
Binary Ninja equivalents for the IDA-specific helpers used by the capa plugin.

Everything the UI needs to touch the disassembler -- names, disassembly text,
bytes, navigation, highlighting, result caching -- is funneled through this
module so that the model/view/item code stays free of direct Binary Ninja API
calls. This is the layer that replaces ``capa.ida.helpers`` and the scattered
``idaapi``/``idc`` calls in the IDA plugin.
"""

import logging
from typing import Optional

from binaryninja import BinaryView, HighlightStandardColor

import capa.render.utils as rutils
import capa.render.result_document as rdoc
from capa.features.address import AbsoluteVirtualAddress

logger = logging.getLogger(__name__)

# capa supports x86/AMD64 with Binary Ninja, matching the IDA plugin.
SUPPORTED_ARCH_NAMES = ("x86", "x86_64")

# highlight color applied to a feature's address when its checkbox is enabled.
# Binary Ninja does not expose arbitrary RGB instruction highlights as cheaply
# as IDA's set_color, so we use a standard color (yellow) instead of 0xE6C700.
DEFAULT_HIGHLIGHT = HighlightStandardColor.YellowHighlightColor

# keys used to cache results inside the .bndb via BinaryView metadata.
# this is the Binary Ninja analog of the IDA netnode the IDA plugin uses.
METADATA_RESULTS = "capa.results"
METADATA_RULES_CACHE_ID = "capa.rules-cache-id"


# ----------------------------------------------------------------------------
# support / capability checks
# ----------------------------------------------------------------------------
def is_supported_arch(bv: BinaryView) -> bool:
    return bv.arch is not None and bv.arch.name in SUPPORTED_ARCH_NAMES


# ----------------------------------------------------------------------------
# names, disassembly, and bytes
# ----------------------------------------------------------------------------
def get_function_name(bv: BinaryView, ea: int) -> str:
    """return the display name for the function starting at ea (or a sub_ fallback)"""
    func = bv.get_function_at(ea)
    if func is not None:
        return func.name

    sym = bv.get_symbol_at(ea)
    if sym is not None:
        return sym.name

    return f"sub_{ea:x}"


def rename_function(bv: BinaryView, ea: int, name: str) -> bool:
    """rename the function starting at ea; returns True on success"""
    func = bv.get_function_at(ea)
    if func is None:
        return False
    try:
        func.name = name
    except Exception as e:
        logger.warning("failed to rename function at 0x%x: %s", ea, e)
        return False
    return True


def get_disasm_line(bv: BinaryView, ea: int) -> str:
    """return the disassembly text for the instruction at ea"""
    try:
        text = bv.get_disassembly(ea)
    except Exception:
        text = None
    return text or ""


def get_bytes(bv: BinaryView, ea: int, size: int) -> bytes:
    try:
        return bv.read(ea, size) or b""
    except Exception:
        return b""


def is_mapped(bv: BinaryView, ea: int) -> bool:
    return bv.is_valid_offset(ea)


def get_func_start(bv: BinaryView, ea: int) -> Optional[int]:
    """return the start address of the function containing ea, or None"""
    funcs = bv.get_functions_containing(ea)
    if not funcs:
        return None
    return funcs[0].start


def file_offset_to_addr(bv: BinaryView, offset: int) -> Optional[int]:
    """map a raw file offset to a virtual address, or None if it isn't mapped.

    The IDA plugin uses ``ida_loader.get_fileregion_ea``; Binary Ninja exposes
    the inverse mapping via ``get_address_for_data_offset``.
    """
    try:
        return bv.get_address_for_data_offset(offset)
    except Exception:
        return None


# ----------------------------------------------------------------------------
# navigation and highlighting (UI side effects)
# ----------------------------------------------------------------------------
def navigate(bv: BinaryView, ea: int):
    """navigate the active Binary Ninja view to ea"""
    try:
        from binaryninjaui import UIContext
    except ImportError:
        logger.debug("binaryninjaui not available, cannot navigate")
        return

    ctx = UIContext.activeContext()
    if ctx is None:
        return
    ctx.navigateForBinaryView(bv, ea)


def set_highlight(bv: BinaryView, ea: int, color: HighlightStandardColor):
    """apply a user instruction highlight at ea across every function containing it"""
    for func in bv.get_functions_containing(ea):
        try:
            func.set_user_instr_highlight(ea, color)
        except Exception as e:
            logger.debug("failed to highlight 0x%x: %s", ea, e)


def clear_highlight(bv: BinaryView, ea: int):
    set_highlight(bv, ea, HighlightStandardColor.NoHighlightColor)


def get_current_address() -> Optional[int]:
    """return the address currently shown in the active view, or None"""
    try:
        from binaryninjaui import UIContext
    except ImportError:
        return None

    ctx = UIContext.activeContext()
    if ctx is None:
        return None
    frame = ctx.getCurrentViewFrame()
    if frame is None:
        return None
    view = frame.getCurrentViewInterface()
    if view is None:
        return None
    try:
        return view.getCurrentOffset()
    except Exception:
        return None


# ----------------------------------------------------------------------------
# input file metadata
# ----------------------------------------------------------------------------
def get_input_file_path(bv: BinaryView) -> str:
    return bv.file.original_filename or bv.file.filename or ""


def retrieve_input_file_md5(bv: BinaryView) -> str:
    import hashlib

    raw = bv.file.raw
    return hashlib.md5(raw.read(0, raw.length)).hexdigest()


# ----------------------------------------------------------------------------
# result caching inside the analysis database (.bndb)
#
# These mirror capa.ida.helpers.{save,load,...}_cached_results but persist into
# BinaryView metadata rather than an IDA netnode.
# ----------------------------------------------------------------------------
def save_cached_results(bv: BinaryView, resdoc: rdoc.ResultDocument):
    logger.debug("saving cached capa results to BinaryView metadata")
    bv.store_metadata(METADATA_RESULTS, resdoc.model_dump_json())


def bv_contains_cached_results(bv: BinaryView) -> bool:
    return bv.get_metadata(METADATA_RESULTS) is not None


def load_and_verify_cached_results(bv: BinaryView) -> Optional[rdoc.ResultDocument]:
    """load cached results, ensuring every match address is still mapped"""
    data = bv.get_metadata(METADATA_RESULTS)
    if not data:
        return None

    doc = rdoc.ResultDocument.model_validate_json(data)

    for rule in rutils.capability_rules(doc):
        for location_, _ in rule.matches:
            location = location_.to_capa()
            if isinstance(location, AbsoluteVirtualAddress):
                ea = int(location)
                if not is_mapped(bv, ea):
                    logger.error(
                        "cached address %s is not a valid location in this database",
                        hex(ea),
                    )
                    return None
    return doc


def save_rules_cache_id(bv: BinaryView, ruleset_id: str):
    bv.store_metadata(METADATA_RULES_CACHE_ID, ruleset_id)


def load_rules_cache_id(bv: BinaryView) -> Optional[str]:
    return bv.get_metadata(METADATA_RULES_CACHE_ID)


def delete_cached_results(bv: BinaryView):
    logger.debug("deleting cached capa data")
    for key in (METADATA_RESULTS, METADATA_RULES_CACHE_ID):
        try:
            bv.remove_metadata(key)
        except KeyError:
            pass


def collect_metadata(bv: BinaryView, rule_paths, extractor, capabilities):
    """build capa Metadata for the result document.

    Reuses capa.loader.collect_metadata so format/arch/os are derived from the
    extractor's global features, exactly like the capa CLI does.
    """
    import capa.loader
    from pathlib import Path
    from capa.features.common import FORMAT_AUTO

    input_path = Path(get_input_file_path(bv))
    return capa.loader.collect_metadata(
        [], input_path, FORMAT_AUTO, list(rule_paths), extractor, capabilities
    )

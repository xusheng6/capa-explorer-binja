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

from typing import Callable, Optional

import binaryninja

from .error import UserCancelledError
from capa.features.extractors.binja.extractor import BinjaFeatureExtractor
from capa.features.extractors.base_extractor import FunctionHandle


class CapaExplorerFeatureExtractor(BinjaFeatureExtractor):
    """BinjaFeatureExtractor that reports progress and supports cancellation.

    Cancellation is checked at the start of every generator method (not just
    once per function), so a large function can be interrupted mid-extraction
    rather than only at function boundaries. When a function total has been set
    via ``set_function_progress_total`` the progress callback also reports a
    determinate "(N of M)" count.

    We drive the progress text / cancellation flag of a BackgroundTaskThread
    rather than IDA's wait box, so we accept plain callbacks to stay decoupled
    from the UI.
    """

    def __init__(
        self,
        bv: binaryninja.BinaryView,
        progress: Optional[Callable[[str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        super().__init__(bv)
        self._progress = progress
        self._is_cancelled = is_cancelled
        self._function_total: Optional[int] = None
        self._function_count = 0

    # ------------------------------------------------------------------ progress
    def set_function_progress_total(self, total: int):
        """enable determinate per-function progress ("N of M")"""
        self._function_total = total
        self._function_count = 0

    def _check_cancel(self):
        if self._is_cancelled is not None and self._is_cancelled():
            raise UserCancelledError("user cancelled")

    def _report(self, text: str):
        if self._progress is not None:
            self._progress(text)

    def _report_function(self, fh: FunctionHandle):
        addr = int(fh.address)
        if self._function_total is not None:
            self._report(
                f"extracting features from function at {hex(addr)} "
                f"({self._function_count + 1} of {self._function_total})"
            )
            self._function_count += 1
        else:
            self._report(f"extracting features from function at {hex(addr)}")

    # ---------------------------------------------------- wrapped extractor calls
    def extract_global_features(self):
        self._check_cancel()
        yield from super().extract_global_features()

    def extract_file_features(self):
        self._check_cancel()
        yield from super().extract_file_features()

    def get_functions(self):
        self._check_cancel()
        for function in super().get_functions():
            self._check_cancel()
            yield function

    def extract_function_features(self, fh: FunctionHandle):
        self._check_cancel()
        self._report_function(fh)
        for feature in super().extract_function_features(fh):
            self._check_cancel()
            yield feature

    def get_basic_blocks(self, fh):
        self._check_cancel()
        for bb in super().get_basic_blocks(fh):
            self._check_cancel()
            yield bb

    def extract_basic_block_features(self, fh, bbh):
        self._check_cancel()
        yield from super().extract_basic_block_features(fh, bbh)

    def get_instructions(self, fh, bbh):
        self._check_cancel()
        for insn in super().get_instructions(fh, bbh):
            self._check_cancel()
            yield insn

    def extract_insn_features(self, fh, bbh, ih):
        self._check_cancel()
        yield from super().extract_insn_features(fh, bbh, ih)

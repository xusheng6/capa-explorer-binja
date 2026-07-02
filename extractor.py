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

    The IDA plugin uses a Qt signal driven by IDA's wait box; in Binary Ninja
    we drive the progress text and cancellation flag of a BackgroundTaskThread
    instead, so we accept plain callbacks here to stay decoupled from the UI.
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

    def _tick(self, text: str):
        if self._is_cancelled is not None and self._is_cancelled():
            raise UserCancelledError("user cancelled")
        if self._progress is not None:
            self._progress(f"extracting features from {text}")

    def extract_function_features(self, fh: FunctionHandle):
        self._tick(f"function at {hex(fh.inner.start)}")
        return super().extract_function_features(fh)

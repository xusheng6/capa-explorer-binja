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
capa explorer Binary Ninja sidebar.

This is the Binary Ninja analog of capa.ida.plugin.form.CapaExplorerForm. Where
the IDA plugin subclasses ``idaapi.PluginForm`` and hooks IDA's UI event system,
here we implement a ``SidebarWidget`` (the modern, idiomatic persistent panel in
Binary Ninja) that:

  * runs analysis on a ``BackgroundTaskThread`` (no blocking wait box),
  * persists settings via ``binaryninja.Settings`` (so they also appear in
    Binary Ninja's native preferences),
  * caches results inside the ``.bndb`` via ``BinaryView`` metadata, and
  * reacts to navigation via ``UIContextNotification`` instead of IDA UI hooks.

Notable non-equivalences vs. the IDA plugin are documented in README.md.
"""

import copy
import logging
import itertools
import collections
from typing import Optional
from pathlib import Path

import binaryninja
from binaryninja import BinaryView, BackgroundTaskThread, execute_on_main_thread
from binaryninjaui import (
    View,
    UIContext,
    ViewFrame,
    ViewLocation,
    SidebarWidget,
    SidebarWidgetType,
    UIContextNotification,
)

import capa.rules
import capa.loader
import capa.version
import capa.features.common
import capa.capabilities.common
import capa.render.result_document
from . import settings
from . import helpers
from capa.rules import Rule
from capa.engine import FeatureSet
from capa.rules.cache import compute_ruleset_cache_identifier
from .qt import QAction, QtGui, QtCore, QtWidgets
from .view import (
    CapaExplorerQtreeView,
    CapaExplorerRulegenEditor,
    CapaExplorerRulegenPreview,
    CapaExplorerRulegenFeatures,
)
from .cache import CapaRuleGenFeatureCache
from .error import UserCancelledError
from .model import CapaExplorerDataModel
from .proxy import (
    CapaExplorerRangeProxyModel,
    CapaExplorerSearchProxyModel,
)
from .extractor import CapaExplorerFeatureExtractor
from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FunctionHandle

logger = logging.getLogger(__name__)

CAPA_OFFICIAL_RULESET_URL = (
    f"https://github.com/mandiant/capa-rules/releases/tag/v{capa.version.__version__}"
)
CAPA_RULESET_DOC_URL = "https://github.com/mandiant/capa/blob/master/doc/rules.md"

WIDGET_NAME = "capa explorer"


def open_capa_sidebar() -> bool:
    """activate the capa explorer sidebar in the active UI context"""
    context = UIContext.activeContext()
    if context is None:
        return False
    sidebar = context.sidebar()
    if sidebar is None:
        return False
    sidebar.activate(WIDGET_NAME)
    return True


def _show_message(title: str, text: str):
    """show a message box on the main thread"""

    def f():
        binaryninja.interaction.show_message_box(title, text)

    execute_on_main_thread(f)


class _BackgroundTask(BackgroundTaskThread):
    """run a target callable on a Binary Ninja background thread

    the target receives this task so it can report progress (``task.progress``)
    and check for cancellation (``task.cancelled``).
    """

    def __init__(self, msg: str, target):
        super().__init__(msg, can_cancel=True)
        self._target = target

    def run(self):
        try:
            self._target(self)
        finally:
            self.finish()


class CapaSettingsDialog(QtWidgets.QDialog):
    """quick settings editor; values are persisted into Binary Ninja Settings"""

    def __init__(self, bv: BinaryView, parent=None):
        super().__init__(parent)
        self.bv = bv

        self.setWindowTitle("capa explorer settings")
        self.setMinimumWidth(500)

        self.edit_rule_path = QtWidgets.QLineEdit(settings.get_rule_path())
        browse = QtWidgets.QPushButton("...")
        browse.setMaximumWidth(30)
        browse.clicked.connect(self._browse)
        rule_path_row = QtWidgets.QHBoxLayout()
        rule_path_row.addWidget(self.edit_rule_path)
        rule_path_row.addWidget(browse)
        rule_path_widget = QtWidgets.QWidget()
        rule_path_widget.setLayout(rule_path_row)

        self.edit_rules_link = QtWidgets.QLabel()
        self.edit_rules_link.setText(
            f'<a href="{CAPA_OFFICIAL_RULESET_URL}">Download and extract official capa rules</a>'
        )
        self.edit_rules_link.setOpenExternalLinks(True)

        self.edit_rule_author = QtWidgets.QLineEdit(settings.get_rulegen_author())

        self.edit_rule_scope = QtWidgets.QComboBox()
        scopes = ("file", "function", "basic block", "instruction")
        self.edit_rule_scope.addItems(scopes)
        try:
            self.edit_rule_scope.setCurrentIndex(
                scopes.index(settings.get_rulegen_scope())
            )
        except ValueError:
            self.edit_rule_scope.setCurrentIndex(scopes.index("function"))

        self.btn_delete_results = QtWidgets.QPushButton("Delete cached capa results")
        if helpers.bv_contains_cached_results(self.bv):
            self.btn_delete_results.clicked.connect(self._delete_cached_results)
        else:
            self.btn_delete_results.setEnabled(False)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel, self
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QFormLayout(self)
        layout.addRow("capa rules path", rule_path_widget)
        layout.addRow("", self.edit_rules_link)
        layout.addRow("", self.btn_delete_results)
        layout.addRow("Rule Generator options", None)
        layout.addRow("Default rule author", self.edit_rule_author)
        layout.addRow("Default rule scope", self.edit_rule_scope)
        layout.addWidget(buttons)

    def _browse(self):
        chosen = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Please select a capa rules directory", self.edit_rule_path.text()
        )
        if chosen:
            self.edit_rule_path.setText(chosen)

    def _delete_cached_results(self):
        helpers.delete_cached_results(self.bv)
        self.btn_delete_results.setEnabled(False)

    def persist(self):
        settings.set_rule_path(self.edit_rule_path.text())
        settings.set_rulegen_author(self.edit_rule_author.text())
        settings.set_rulegen_scope(self.edit_rule_scope.currentText())


class CapaExplorerSidebarWidget(SidebarWidget, UIContextNotification):
    """main capa explorer panel"""

    def __init__(self, name: str, frame: ViewFrame, data: BinaryView):
        SidebarWidget.__init__(self, name)
        UIContextNotification.__init__(self)
        self.m_actionHandler.setupActionHandler(self)

        self.bv: BinaryView = data
        self.frame: ViewFrame = frame

        # caches used to speed up analysis - these must be init to None
        self.resdoc_cache: Optional[capa.render.result_document.ResultDocument] = None
        self.program_analysis_ruleset_cache: Optional[capa.rules.RuleSet] = None
        self.rulegen_feature_extractor: Optional[CapaExplorerFeatureExtractor] = None
        self.rulegen_feature_cache: Optional[CapaRuleGenFeatureCache] = None
        self.rulegen_ruleset_cache: Optional[capa.rules.RuleSet] = None
        self.rulegen_current_function: Optional[FunctionHandle] = None

        self._status_analysis = "Click Analyze to get started..."
        self._status_rulegen = "Click Analyze to get started..."

        # lifecycle + re-entrancy guards for background analysis
        self._alive = True
        self._analysis_running = False
        # bumped on each analyze; a background task whose token no longer
        # matches discards its (now superseded) UI update.
        self._analysis_task_token = 0

        self._build_interface()

        UIContext.registerNotification(self)

    def __del__(self):
        self._alive = False
        try:
            self.model_data.clear_all_highlights()
        except Exception:
            pass
        try:
            UIContext.unregisterNotification(self)
        except Exception:
            pass

    def _post(self, fn):
        """run fn on the UI thread, skipping it if this widget was torn down.

        Background tasks capture ``self``; if the view/BinaryView is closed while
        a task is still running, the deferred callback would otherwise touch a
        deleted C++ widget and hard-crash Binary Ninja.
        """

        def guarded():
            if not getattr(self, "_alive", False):
                return
            try:
                fn()
            except RuntimeError:
                # the underlying C++ object was deleted while the task ran
                pass

        execute_on_main_thread(guarded)

    # ------------------------------------------------------------------ UI
    def _build_interface(self):
        # model <- range filter <- search filter <- view
        self.model_data = CapaExplorerDataModel(self.bv)

        self.range_model_proxy = CapaExplorerRangeProxyModel()
        self.range_model_proxy.setSourceModel(self.model_data)

        self.search_model_proxy = CapaExplorerSearchProxyModel()
        self.search_model_proxy.setSourceModel(self.range_model_proxy)

        self.view_tree = CapaExplorerQtreeView(self.search_model_proxy, self.bv, self)

        self.view_tabs = QtWidgets.QTabWidget()
        self.view_tabs.addTab(self._build_program_tab(), "Program Analysis")
        self.view_tabs.addTab(self._build_rulegen_tab(), "Rule Generator")
        self.view_tabs.currentChanged.connect(self.slot_tabview_change)

        # hamburger menu in the tab bar's top-right corner: program-analysis
        # view options plus Settings
        self.view_tabs.setCornerWidget(
            self._build_hamburger_menu(), QtCore.Qt.TopRightCorner
        )

        self.view_status_label = QtWidgets.QLabel(self._status_analysis)
        self.view_status_label.setAlignment(QtCore.Qt.AlignLeft)
        self.view_status_label.setWordWrap(True)

        # buttons
        self.view_analyze_button = QtWidgets.QPushButton("Analyze")
        self.view_reset_button = QtWidgets.QPushButton("Reset Selections")
        self.view_save_button = QtWidgets.QPushButton("Export")

        self.view_analyze_button.clicked.connect(self.slot_analyze)
        self.view_reset_button.clicked.connect(self.slot_reset)
        self.view_save_button.clicked.connect(self.slot_save)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.view_save_button)
        button_layout.addWidget(self.view_analyze_button)
        button_layout.addWidget(self.view_reset_button)
        button_layout.addStretch(3)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(self.view_tabs)
        layout.addLayout(button_layout)
        layout.addWidget(self.view_status_label)
        self.setLayout(layout)

    def _build_hamburger_menu(self) -> QtWidgets.QToolButton:
        """build the top-right corner menu for view options and Settings"""
        # kept as QActions (not checkboxes) so isChecked()/setChecked() still work
        # for the rest of the code that reads these toggles.
        self.view_limit_results_by_function = QAction(
            "Limit results to current function", self
        )
        self.view_limit_results_by_function.setCheckable(True)
        self.view_limit_results_by_function.toggled.connect(
            self.slot_checkbox_limit_by_changed
        )

        self.view_show_results_by_function = QAction("Show matches by function", self)
        self.view_show_results_by_function.setCheckable(True)
        self.view_show_results_by_function.toggled.connect(
            self.slot_checkbox_show_results_by_function_changed
        )

        self.view_settings_action = QAction("Settings…", self)
        self.view_settings_action.triggered.connect(self.slot_settings)

        menu = QtWidgets.QMenu(self)
        menu.addAction(self.view_limit_results_by_function)
        menu.addAction(self.view_show_results_by_function)
        menu.addSeparator()
        menu.addAction(self.view_settings_action)

        button = QtWidgets.QToolButton(self)
        button.setText("☰")  # hamburger glyph
        button.setToolTip("View options")
        button.setAutoRaise(True)
        button.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        button.setMenu(menu)
        return button

    def _build_program_tab(self) -> QtWidgets.QWidget:
        self.view_search_bar = QtWidgets.QLineEdit()
        self.view_search_bar.setPlaceholderText("search...")
        self.view_search_bar.setClearButtonEnabled(True)
        self.view_search_bar.textChanged.connect(self.slot_limit_results_to_search)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.view_search_bar)
        layout.addWidget(self.view_tree)

        tab = QtWidgets.QWidget()
        tab.setLayout(layout)
        return tab

    def _build_rulegen_tab(self) -> QtWidgets.QWidget:
        font = QtGui.QFont()
        font.setBold(True)
        font.setPointSize(11)

        label_preview = QtWidgets.QLabel("Preview")
        label_preview.setFont(font)
        label_editor = QtWidgets.QLabel("Editor")
        label_editor.setFont(font)
        self.view_rulegen_header_label = QtWidgets.QLabel("Features")
        self.view_rulegen_header_label.setFont(font)

        self.view_rulegen_limit_features_by_ea = QtWidgets.QCheckBox(
            "Limit features to current disassembly address"
        )
        self.view_rulegen_limit_features_by_ea.stateChanged.connect(
            self.slot_checkbox_limit_features_by_ea
        )

        self.view_rulegen_status_label = QtWidgets.QLabel("")
        self.view_rulegen_status_label.setWordWrap(True)

        self.view_rulegen_search = QtWidgets.QLineEdit()
        self.view_rulegen_search.setPlaceholderText("search...")
        self.view_rulegen_search.setClearButtonEnabled(True)
        self.view_rulegen_search.textChanged.connect(
            self.slot_limit_rulegen_features_to_search
        )

        self.view_rulegen_preview = CapaExplorerRulegenPreview(self.bv, parent=self)
        self.view_rulegen_editor = CapaExplorerRulegenEditor(
            self.view_rulegen_preview, parent=self
        )
        self.view_rulegen_features = CapaExplorerRulegenFeatures(
            self.view_rulegen_editor, self.bv, parent=self
        )

        self.view_rulegen_preview.textChanged.connect(self.slot_rulegen_preview_update)
        self.view_rulegen_editor.updated.connect(self.slot_rulegen_editor_update)

        self.set_rulegen_preview_border_neutral()

        right_top_layout = QtWidgets.QVBoxLayout()
        right_top_layout.addWidget(label_preview)
        right_top_layout.addWidget(self.view_rulegen_preview, 45)
        right_top_layout.addWidget(self.view_rulegen_status_label)
        right_top = QtWidgets.QWidget()
        right_top.setLayout(right_top_layout)

        right_bottom_layout = QtWidgets.QVBoxLayout()
        right_bottom_layout.addWidget(label_editor)
        right_bottom_layout.addWidget(self.view_rulegen_editor, 65)
        right_bottom = QtWidgets.QWidget()
        right_bottom.setLayout(right_bottom_layout)

        left_layout = QtWidgets.QVBoxLayout()
        left_layout.addWidget(self.view_rulegen_header_label)
        left_layout.addWidget(self.view_rulegen_limit_features_by_ea)
        left_layout.addWidget(self.view_rulegen_search)
        left_layout.addWidget(self.view_rulegen_features)
        left = QtWidgets.QWidget()
        left.setLayout(left_layout)

        splitter_right = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter_right.addWidget(right_top)
        splitter_right.addWidget(right_bottom)

        splitter_main = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter_main.addWidget(left)
        splitter_main.addWidget(splitter_right)

        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(splitter_main)
        tab = QtWidgets.QWidget()
        tab.setLayout(layout)
        return tab

    # ------------------------------------------------- UIContextNotification
    def notifyViewChanged(self, frame: ViewFrame):
        if frame is not None:
            self.frame = frame

    def OnAddressChange(
        self, context: UIContext, frame: ViewFrame, view: View, location: ViewLocation
    ):
        if not self.isVisible():
            return

        ea: Optional[int] = None
        try:
            ea = location.getOffset()
        except Exception:
            ea = helpers.get_current_address()

        if ea is None or not self.bv.is_valid_offset(ea):
            return

        tab = self.view_tabs.currentIndex()
        if tab == 0 and self.view_limit_results_by_function.isChecked():
            self._limit_results_to_function(ea)
            self.view_tree.reset_ui()
        elif tab == 1 and self.view_rulegen_limit_features_by_ea.isChecked():
            self.view_rulegen_features.filter_items_by_ea(ea)

    # ------------------------------------------------------------- analysis
    def _ensure_rule_path(self) -> Optional[Path]:
        """resolve the rules directory, prompting the user if it isn't set"""
        path = settings.get_rule_path()
        if path and Path(path).exists():
            return Path(path)

        # Binary Ninja's native directory picker doesn't show explanatory text,
        # so tell the user what to select (and where to get rules) first. This
        # runs on the main thread, so the message box is modal and blocks until
        # dismissed before the picker opens.
        binaryninja.log_warn(
            f"capa: select a directory of capa rules. Download the official rules from {CAPA_OFFICIAL_RULESET_URL}"
        )
        binaryninja.interaction.show_message_box(
            "capa explorer",
            "capa needs a directory of rules to analyze with.\n\n"
            "Click OK, then choose your local capa-rules directory.\n\n"
            "If you don't have the rules yet, download and extract the release that matches "
            f"your capa version from:\n{CAPA_OFFICIAL_RULESET_URL}",
        )
        chosen = binaryninja.interaction.get_directory_name_input(
            "Select your capa rules directory"
        )
        if not chosen:
            _show_message(
                "capa explorer", "Analysis requires a directory of capa rules."
            )
            return None

        chosen = str(chosen)
        if not Path(chosen).exists():
            logger.error("rule path %s does not exist or cannot be accessed", chosen)
            return None

        settings.set_rule_path(chosen)
        return Path(chosen)

    def _ask_use_cache(self) -> Optional[bool]:
        """decide whether to load cached results.

        returns True (load cache), False (reanalyze), or None (user cancelled).
        """
        if not helpers.bv_contains_cached_results(self.bv):
            return False

        try:
            cached = helpers.load_and_verify_cached_results(self.bv)
        except Exception as e:
            logger.warning("failed to verify cached results, reanalyzing: %s", e)
            return False

        if cached is None:
            return False

        ts = cached.meta.timestamp.strftime("%Y-%m-%d at %H:%M:%S")
        choice = binaryninja.interaction.get_choice_input(
            f"This database contains capa results generated on {ts}.\nLoad existing data or analyze again?",
            "capa explorer",
            ["Load cached results", "Reanalyze program"],
        )
        if choice is None:
            return None
        return choice == 0

    def analyze_program(self):
        if self._analysis_running:
            _show_message(
                "capa explorer",
                "capa analysis is already running; please wait for it to finish.",
            )
            return

        rule_path = self._ensure_rule_path()
        if rule_path is None:
            self.set_view_status_label("Click Analyze to get started...")
            return

        from_cache = self._ask_use_cache()
        if from_cache is None:
            return

        # reset model/view before kicking off background analysis
        self.range_model_proxy.invalidate()
        self.search_model_proxy.invalidate()
        self.model_data.reset()
        self.model_data.clear()
        self.reset_view_tree()
        self.set_view_status_label("Analyzing...")

        by_function = self.view_show_results_by_function.isChecked()
        self._analysis_running = True
        self._analysis_task_token += 1
        token = self._analysis_task_token
        task = _BackgroundTask(
            "capa: analyzing program...",
            lambda t: self._run_program_analysis(
                t, rule_path, from_cache, by_function, token
            ),
        )
        task.start()

    def _run_program_analysis(
        self,
        task: _BackgroundTask,
        rule_path: Path,
        from_cache: bool,
        by_function: bool,
        token: int,
    ):
        try:

            def on_load_rule(_, i, total):
                task.progress = f"capa: loading rules ({i + 1} of {total})"
                if task.cancelled:
                    raise UserCancelledError()

            if from_cache:
                task.progress = "capa: loading rules"
                ruleset = capa.rules.get_rules([rule_path], on_load_rule=on_load_rule)
                resdoc = helpers.load_and_verify_cached_results(self.bv)
                if resdoc is None:
                    _show_message(
                        "capa explorer",
                        "Cached results are not valid. Please reanalyze your program.",
                    )
                    self._post(lambda: self._fail_analysis())
                    return

                status_rules = f"{rule_path} ({ruleset.source_rule_count} rules)"
                if compute_ruleset_cache_identifier(
                    ruleset
                ) != helpers.load_rules_cache_id(self.bv):
                    binaryninja.log_warn(
                        "capa: cached results were generated using different rules; reanalyze to refresh."
                    )
                    status_rules = "no rules matched for cache"
                ts = resdoc.meta.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                status = f"capa rules: {status_rules}, cached results (created {ts})"
            else:
                task.progress = "capa: initializing feature extractor"
                extractor = CapaExplorerFeatureExtractor(
                    self.bv,
                    progress=lambda text: setattr(task, "progress", f"capa: {text}"),
                    is_cancelled=lambda: task.cancelled,
                )
                extractor.set_function_progress_total(
                    len(tuple(extractor.get_functions()))
                )

                task.progress = "capa: loading rules"
                self.program_analysis_ruleset_cache = capa.rules.get_rules(
                    [rule_path], on_load_rule=on_load_rule
                )

                # matching may mutate rule instances, so work on a copy
                ruleset = copy.deepcopy(self.program_analysis_ruleset_cache)

                task.progress = "capa: extracting features and matching rules"
                capabilities = capa.capabilities.common.find_capabilities(
                    ruleset, extractor, disable_progress=True
                )

                meta = helpers.collect_metadata(
                    self.bv, [rule_path], extractor, capabilities
                )
                meta.analysis.layout = capa.loader.compute_layout(
                    ruleset, extractor, capabilities.matches
                )

                try:
                    if capa.capabilities.common.has_static_limitation(
                        ruleset, capabilities, is_standalone=False
                    ):
                        binaryninja.log_warn(
                            "capa: encountered file limitation warnings during analysis"
                        )
                except Exception as e:
                    logger.debug("failed to check for static limitations: %s", e)

                task.progress = "capa: collecting results"
                resdoc = capa.render.result_document.ResultDocument.from_capa(
                    meta, ruleset, capabilities.matches
                )

                task.progress = "capa: caching results in database"
                helpers.save_cached_results(self.bv, resdoc)
                helpers.save_rules_cache_id(
                    self.bv, compute_ruleset_cache_identifier(ruleset)
                )

                status = f"capa rules: {rule_path} ({self.program_analysis_ruleset_cache.source_rule_count} rules)"

            self.resdoc_cache = resdoc
            if self.program_analysis_ruleset_cache is None:
                self.program_analysis_ruleset_cache = ruleset

            self._status_analysis = status
            self._post(
                lambda: self._finish_program_analysis(status, by_function, token)
            )
        except UserCancelledError:
            logger.info("user cancelled analysis")
            self._post(lambda: self._fail_analysis("Click Analyze to get started..."))
        except Exception as e:
            logger.exception("failed to analyze program: %s", e)
            _show_message("capa explorer", f"Failed to analyze program: {e}")
            self._post(lambda: self._fail_analysis())
        finally:
            self._analysis_running = False

    def _finish_program_analysis(self, status: str, by_function: bool, token=None):
        if token is not None and token != self._analysis_task_token:
            return
        try:
            assert self.resdoc_cache is not None
            self.model_data.render_capa_doc(self.resdoc_cache, by_function)
            self.reset_view_tree()
            self.set_view_status_label(status)
        except Exception as e:
            logger.exception("failed to render results: %s", e)
            self.set_view_status_label("Click Analyze to get started...")

    def _fail_analysis(self, status: str = "Click Analyze to get started..."):
        self.set_view_status_label(status)

    def _rerender_program(self):
        if self.resdoc_cache is None:
            return
        self.model_data.reset()
        self.model_data.clear()
        self.model_data.render_capa_doc(
            self.resdoc_cache, self.view_show_results_by_function.isChecked()
        )
        self.reset_view_tree()

    # ----------------------------------------------------------- rule generator
    def analyze_function(self):
        if self._analysis_running:
            _show_message(
                "capa explorer",
                "capa analysis is already running; please wait for it to finish.",
            )
            return

        rule_path = self._ensure_rule_path()
        if rule_path is None:
            self.set_view_status_label("Click Analyze to get started...")
            return

        self.reset_function_analysis_views(is_analyze=True)
        self.set_view_status_label("Loading...")

        # UIContext access must happen on the UI thread, so resolve the current
        # address here and hand it to the worker.
        ea = helpers.get_current_address()
        self._analysis_running = True
        self._analysis_task_token += 1
        token = self._analysis_task_token
        task = _BackgroundTask(
            "capa: extracting function features...",
            lambda t: self._run_function_analysis(t, rule_path, ea, token),
        )
        task.start()

    def _run_function_analysis(
        self, task: _BackgroundTask, rule_path: Path, ea: Optional[int], token: int
    ):
        try:
            if self.rulegen_ruleset_cache is None:
                task.progress = "capa: loading rules"

                def on_load_rule(_, i, total):
                    task.progress = f"capa: loading rules ({i + 1} of {total})"
                    if task.cancelled:
                        raise UserCancelledError()

                self.rulegen_ruleset_cache = capa.rules.get_rules(
                    [rule_path], on_load_rule=on_load_rule
                )

            ruleset = copy.deepcopy(self.rulegen_ruleset_cache)

            self.rulegen_current_function = None

            if (
                self.rulegen_feature_cache is None
                or self.rulegen_feature_extractor is None
            ):
                task.progress = "capa: performing one-time file analysis"
                self.rulegen_feature_extractor = CapaExplorerFeatureExtractor(
                    self.bv, is_cancelled=lambda: task.cancelled
                )
                self.rulegen_feature_cache = CapaRuleGenFeatureCache(
                    self.rulegen_feature_extractor
                )

            # resolve the function currently shown in the disassembly view
            if ea is not None:
                funcs = self.bv.get_functions_containing(ea)
                if funcs:
                    func = funcs[0]
                    self.rulegen_current_function = FunctionHandle(
                        address=AbsoluteVirtualAddress(func.start), inner=func
                    )

            task.progress = "capa: generating function rule matches"
            all_function_features: FeatureSet = collections.defaultdict(set)
            if self.rulegen_current_function is not None:
                _, func_matches, bb_matches, insn_matches = (
                    self.rulegen_feature_cache.find_code_capabilities(
                        ruleset, self.rulegen_current_function
                    )
                )
                all_function_features.update(
                    self.rulegen_feature_cache.get_all_function_features(
                        self.rulegen_current_function
                    )
                )
                for name, result in itertools.chain(
                    func_matches.items(), bb_matches.items(), insn_matches.items()
                ):
                    rule = ruleset[name]
                    if rule.is_subscope_rule():
                        continue
                    for addr, _ in result:
                        all_function_features[
                            capa.features.common.MatchedRule(name)
                        ].add(addr)

            task.progress = "capa: generating file rule matches"
            all_file_features: FeatureSet = collections.defaultdict(set)
            _, file_matches = self.rulegen_feature_cache.find_file_capabilities(ruleset)
            all_file_features.update(self.rulegen_feature_cache.get_all_file_features())
            for name, result in file_matches.items():
                rule = ruleset[name]
                if rule.is_subscope_rule():
                    continue
                for addr, _ in result:
                    all_file_features[capa.features.common.MatchedRule(name)].add(addr)

            func_address = (
                self.rulegen_current_function.address
                if self.rulegen_current_function
                else None
            )
            status = f"capa rules: {rule_path}"
            self._post(
                lambda: self._finish_function_analysis(
                    func_address,
                    all_file_features,
                    all_function_features,
                    status,
                    token,
                )
            )
        except UserCancelledError:
            logger.info("user cancelled analysis")
            self._post(lambda: self._fail_analysis("Click Analyze to get started..."))
        except Exception as e:
            logger.exception("failed to analyze function: %s", e)
            _show_message("capa explorer", f"Failed to analyze function: {e}")
            self._post(lambda: self._fail_analysis())
        finally:
            self._analysis_running = False

    def _finish_function_analysis(
        self, func_address, all_file_features, all_function_features, status, token=None
    ):
        if token is not None and token != self._analysis_task_token:
            return
        try:
            self.view_rulegen_preview.load_preview_meta(
                # func_address is an AbsoluteVirtualAddress (an int subclass), so
                # hex(func_address) in load_preview_meta works directly.
                int(func_address) if func_address is not None else None,
                settings.get_rulegen_author(),
                settings.get_rulegen_scope(),
            )
            self.view_rulegen_features.load_features(
                all_file_features, all_function_features
            )
            self.set_view_status_label(status)
        except Exception as e:
            logger.exception("failed to render rule generator views: %s", e)
            self.set_view_status_label("Click Analyze to get started...")

    def update_rule_status(self, rule_text: str):
        rule: capa.rules.Rule
        rules: list[Rule]
        ruleset: capa.rules.RuleSet

        if self.view_rulegen_editor.invisibleRootItem().childCount() == 0:
            self.set_rulegen_preview_border_neutral()
            self.view_rulegen_status_label.clear()
            return

        if self.rulegen_ruleset_cache is None or self.rulegen_feature_cache is None:
            self.set_rulegen_status("Click Analyze to begin building a rule")
            return

        self.set_rulegen_preview_border_error()

        try:
            rule = capa.rules.Rule.from_yaml(rule_text)
            from capa.render.result_document import RuleMetadata

            _ = RuleMetadata.from_capa(rule)
        except Exception as e:
            self.set_rulegen_status(f"Failed to compile rule ({e})")
            return

        rules = copy.deepcopy(
            [
                r
                for r in self.rulegen_ruleset_cache.rules.values()
                if not r.is_subscope_rule()
            ]
        )
        rules.append(rule)

        try:
            ruleset = capa.rules.RuleSet(
                list(capa.rules.get_rules_and_dependencies(rules, rule.name))
            )
        except Exception as e:
            self.set_rulegen_status(f"Failed to create ruleset ({e})")
            return

        is_match: bool = False
        if self.rulegen_current_function is not None and any(
            s in rule.scopes
            for s in (
                capa.rules.Scope.FUNCTION,
                capa.rules.Scope.BASIC_BLOCK,
                capa.rules.Scope.INSTRUCTION,
            )
        ):
            try:
                _, func_matches, bb_matches, insn_matches = (
                    self.rulegen_feature_cache.find_code_capabilities(
                        ruleset, self.rulegen_current_function
                    )
                )
            except Exception as e:
                self.set_rulegen_status(
                    f"Failed to create function rule matches from rule set ({e})"
                )
                return

            if capa.rules.Scope.FUNCTION in rule.scopes and rule.name in func_matches:
                is_match = True
            elif (
                capa.rules.Scope.BASIC_BLOCK in rule.scopes and rule.name in bb_matches
            ):
                is_match = True
            elif (
                capa.rules.Scope.INSTRUCTION in rule.scopes
                and rule.name in insn_matches
            ):
                is_match = True
        elif capa.rules.Scope.FILE in rule.scopes:
            try:
                _, file_matches = self.rulegen_feature_cache.find_file_capabilities(
                    ruleset
                )
            except Exception as e:
                self.set_rulegen_status(
                    f"Failed to create file rule matches from rule set ({e})"
                )
                return
            if rule.name in file_matches:
                is_match = True
        else:
            is_match = False

        if is_match:
            self.set_rulegen_preview_border_success()
            self.set_rulegen_status("Rule compiled and matched")
        else:
            self.set_rulegen_preview_border_warn()
            self.set_rulegen_status("Rule compiled, but not matched")

    # ------------------------------------------------------------- reset/views
    def reset_view_tree(self):
        self.view_limit_results_by_function.setChecked(False)
        self.view_search_bar.setText("")
        self.view_tree.reset_ui()

    def reset_program_analysis_views(self):
        self.model_data.reset()
        self.reset_view_tree()

    def reset_function_analysis_views(self, is_analyze=False):
        self.view_rulegen_features.reset_view()
        self.view_rulegen_editor.reset_view()
        self.view_rulegen_preview.reset_view()
        self.view_rulegen_search.clear()
        self.view_rulegen_limit_features_by_ea.setChecked(False)
        self.set_rulegen_preview_border_neutral()
        self.rulegen_current_function = None
        self.view_rulegen_status_label.clear()

        if not is_analyze:
            self.rulegen_ruleset_cache = None
            self.set_view_status_label("Click Analyze to get started...")

    def set_rulegen_status(self, text):
        self.view_rulegen_status_label.setText(text)

    def set_rulegen_preview_border_error(self):
        self.view_rulegen_preview.setStyleSheet("border: 3px solid red")

    def set_rulegen_preview_border_neutral(self):
        self.view_rulegen_preview.setStyleSheet("border: 3px solid grey")

    def set_rulegen_preview_border_warn(self):
        self.view_rulegen_preview.setStyleSheet("border: 3px solid yellow")

    def set_rulegen_preview_border_success(self):
        self.view_rulegen_preview.setStyleSheet("border: 3px solid green")

    def set_view_status_label(self, text):
        self.view_status_label.setText(text)

    # ---------------------------------------------------------------- slots
    def slot_tabview_change(self, index):
        if index not in (0, 1):
            return

        status_prev = self.view_status_label.text()
        if index == 0:
            self.set_view_status_label(self._status_analysis)
            self._status_rulegen = status_prev
            self.view_reset_button.setText("Reset Selections")
        elif index == 1:
            self.set_view_status_label(self._status_rulegen)
            self._status_analysis = status_prev
            self.view_reset_button.setText("Clear")

    def slot_analyze(self):
        if not helpers.is_supported_arch(self.bv):
            _show_message(
                "capa explorer",
                "capa with Binary Ninja currently supports x86 (32- and 64-bit) only.",
            )
            return

        if self.view_tabs.currentIndex() == 0:
            self.analyze_program()
        elif self.view_tabs.currentIndex() == 1:
            self.analyze_function()

    def slot_reset(self):
        if self.view_tabs.currentIndex() == 0:
            self.reset_program_analysis_views()
        elif self.view_tabs.currentIndex() == 1:
            self.reset_function_analysis_views()

    def slot_save(self):
        if self.view_tabs.currentIndex() == 0:
            self.save_program_analysis()
        elif self.view_tabs.currentIndex() == 1:
            self.save_function_analysis()

    def slot_settings(self):
        dialog = CapaSettingsDialog(self.bv, parent=self)
        if dialog.exec_():
            dialog.persist()

    def slot_rulegen_editor_update(self):
        self.update_rule_status(self.view_rulegen_preview.toPlainText())

    def slot_rulegen_preview_update(self):
        rule_text = self.view_rulegen_preview.toPlainText()
        self.view_rulegen_editor.load_features_from_yaml(rule_text, False)
        self.update_rule_status(rule_text)

    def slot_limit_rulegen_features_to_search(self, text):
        self.view_rulegen_features.filter_items_by_text(text)

    def slot_checkbox_limit_by_changed(self, state):
        if state:
            self._limit_results_to_function(helpers.get_current_address())
        else:
            self.range_model_proxy.reset_address_range_filter()
        self.view_tree.reset_ui()

    def slot_checkbox_limit_features_by_ea(self, state):
        if state:
            ea = helpers.get_current_address()
            if ea is not None:
                self.view_rulegen_features.filter_items_by_ea(ea)
        else:
            self.view_rulegen_features.show_all_items()

    def slot_checkbox_show_results_by_function_changed(self, state):
        self._rerender_program()

    def slot_limit_results_to_search(self, text):
        self.search_model_proxy.set_query(text)
        self.view_tree.reset_ui(should_sort=False)

    def _limit_results_to_function(self, ea: Optional[int]):
        """limit results to the function containing ea (by virtual address range)"""
        func_start = helpers.get_func_start(self.bv, ea) if ea is not None else None
        if func_start is not None:
            func = self.bv.get_function_at(func_start)
            if func is not None and func.basic_blocks:
                min_ea = min(bb.start for bb in func.basic_blocks)
                max_ea = max(bb.end for bb in func.basic_blocks)
                self.range_model_proxy.add_address_range_filter(min_ea, max_ea)
                return
        # no function: display nothing (assume address never -1)
        self.range_model_proxy.add_address_range_filter(-1, -1)

    # ---------------------------------------------------------------- save
    def save_program_analysis(self):
        if not self.resdoc_cache:
            _show_message("capa explorer", "No program analysis to save.")
            return

        path = binaryninja.interaction.get_save_filename_input(
            "Save capa results", "json"
        )
        if not path:
            return
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        Path(path).write_bytes(self.resdoc_cache.model_dump_json().encode("utf-8"))
        binaryninja.log_info(f"capa: saved results to {path}")

    def save_function_analysis(self):
        text = self.view_rulegen_preview.toPlainText()
        if not text:
            _show_message("capa explorer", "No rule to save.")
            return

        path = binaryninja.interaction.get_save_filename_input("Save capa rule", "yml")
        if not path:
            return
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        Path(path).write_bytes(text.encode("utf-8"))
        binaryninja.log_info(f"capa: saved rule to {path}")


class CapaExplorerSidebarWidgetType(SidebarWidgetType):
    """registers the capa explorer panel with Binary Ninja's sidebar"""

    def __init__(self):
        icon = self._make_icon()
        SidebarWidgetType.__init__(self, icon, WIDGET_NAME)

    @staticmethod
    def _make_icon() -> "QtGui.QImage":
        # try the capa logo bundled with the IDA plugin; fall back to text.
        try:
            from .icon import ICON

            image = QtGui.QImage()
            if image.loadFromData(ICON):
                return image.scaled(
                    56, 56, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation
                )
        except Exception:
            pass

        image = QtGui.QImage(56, 56, QtGui.QImage.Format_RGB32)
        image.fill(0)
        p = QtGui.QPainter()
        p.begin(image)
        p.setFont(QtGui.QFont("Open Sans", 36))
        p.setPen(QtGui.QColor(255, 255, 255, 255))
        p.drawText(QtCore.QRectF(0, 0, 56, 56), QtCore.Qt.AlignCenter, "ca")
        p.end()
        return image

    def createWidget(self, frame: ViewFrame, data: BinaryView) -> SidebarWidget:
        return CapaExplorerSidebarWidget(WIDGET_NAME, frame, data)

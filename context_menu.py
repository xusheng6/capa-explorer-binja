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
Global "Open capa explorer" right-click action.

Registers a UIAction and injects it into every context menu via
UIContextNotification.OnContextMenuCreated, so users can open the sidebar from
anywhere (idea adapted from kevinmuoz/capa's context_menu.py).
"""

from __future__ import annotations

import logging
from typing import Optional

import binaryninja
from binaryninjaui import (
    Menu,
    View,
    UIAction,
    UIContext,
    UIActionContext,
    UIActionHandler,
    UIContextNotification,
)

from .form import open_capa_sidebar

logger = logging.getLogger(__name__)

MENU_GROUP = "capa"
ACTION_NAME = f"{MENU_GROUP}\\Open capa explorer"


def _open(ctx: UIActionContext) -> None:
    del ctx

    def do_open() -> None:
        if not open_capa_sidebar():
            binaryninja.log_warn("capa: unable to open the capa explorer sidebar")

    binaryninja.execute_on_main_thread(do_open)


def _is_available(ctx: UIActionContext) -> bool:
    return getattr(ctx, "binaryView", None) is not None


class _CapaContextMenuNotification(UIContextNotification):
    def OnContextMenuCreated(self, context: UIContext, view: View, menu: Menu) -> None:
        del context, view
        if menu is None:
            return
        try:
            if ACTION_NAME in menu.getActions():
                menu.removeAction(ACTION_NAME)
            menu.addAction(ACTION_NAME, MENU_GROUP, 0)
        except Exception as e:
            logger.debug("failed to inject capa context menu action: %s", e)


_notification: Optional[_CapaContextMenuNotification] = None
_action_registered = False


def register_context_menu() -> None:
    """register the action + context-menu notification (idempotent)"""
    global _notification, _action_registered

    if not _action_registered:
        if not UIAction.isActionRegistered(ACTION_NAME):
            UIAction.registerAction(ACTION_NAME)
        UIActionHandler.globalActions().bindAction(
            ACTION_NAME, UIAction(_open, _is_available)
        )
        _action_registered = True

    if _notification is None:
        _notification = _CapaContextMenuNotification()
        binaryninja.execute_on_main_thread(
            lambda: UIContext.registerNotification(_notification)
        )

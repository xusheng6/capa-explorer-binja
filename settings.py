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
Persisted plugin settings backed by Binary Ninja's ``Settings`` store.

Unlike the IDA plugin (which uses ``ida_settings`` and stores per-user values in
the registry/INI), Binary Ninja has a first-class settings system. Registering
our settings here means they also show up in Binary Ninja's native preferences
UI (Edit > Preferences > Settings, filter for "capa"), which is the idiomatic
place for users to configure a plugin.
"""

import json
import logging

import binaryninja
from binaryninja import Settings

logger = logging.getLogger(__name__)

GROUP = "capa"

RULE_PATH = "capa.rulesPath"
RULEGEN_AUTHOR = "capa.rulegenAuthor"
RULEGEN_SCOPE = "capa.rulegenScope"

# settings that affect the binary's analysis must not be stored in the database,
# only at the user/project level; these are pure UI preferences.
_IGNORE = ["SettingsProjectScope", "SettingsResourceScope"]


def register():
    """register the capa settings group and schema (idempotent)"""
    settings = Settings()
    settings.register_group(GROUP, "capa")

    schema = {
        RULE_PATH: {
            "title": "capa rules directory",
            "type": "string",
            "default": "",
            "description": "Local directory containing capa rules used for analysis.",
            "uiSelectionAction": "directory",
            "ignore": _IGNORE,
        },
        RULEGEN_AUTHOR: {
            "title": "Rule Generator: default author",
            "type": "string",
            "default": "<insert_author>",
            "description": "Default author written into rules created with the Rule Generator.",
            "ignore": _IGNORE,
        },
        RULEGEN_SCOPE: {
            "title": "Rule Generator: default scope",
            "type": "string",
            "default": "function",
            "enum": ["file", "function", "basic block", "instruction"],
            "description": "Default static scope written into rules created with the Rule Generator.",
            "ignore": _IGNORE,
        },
    }

    for key, value in schema.items():
        if not settings.register_setting(key, json.dumps(value)):
            logger.debug(
                "failed to register capa setting %s (it may already be registered)", key
            )


def get_rule_path() -> str:
    return Settings().get_string(RULE_PATH)


def set_rule_path(path: str):
    Settings().set_string(
        RULE_PATH, path, scope=binaryninja.SettingsScope.SettingsUserScope
    )


def get_rulegen_author() -> str:
    return Settings().get_string(RULEGEN_AUTHOR) or "<insert_author>"


def set_rulegen_author(author: str):
    Settings().set_string(
        RULEGEN_AUTHOR, author, scope=binaryninja.SettingsScope.SettingsUserScope
    )


def get_rulegen_scope() -> str:
    return Settings().get_string(RULEGEN_SCOPE) or "function"


def set_rulegen_scope(scope: str):
    Settings().set_string(
        RULEGEN_SCOPE, scope, scope=binaryninja.SettingsScope.SettingsUserScope
    )

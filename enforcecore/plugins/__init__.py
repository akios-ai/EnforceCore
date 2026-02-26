# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Plugin and extensibility system for EnforceCore."""

from enforcecore.plugins.base import (
    AuditBackendPlugin,
    GuardPlugin,
    GuardResult,
    PluginInfo,
    RedactorPlugin,
    RedactResult,
)
from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
    on_post_call,
    on_pre_call,
    on_redaction,
    on_violation,
)
from enforcecore.plugins.manager import PluginLoadError, PluginManager

__all__ = [
    "AuditBackendPlugin",
    "GuardPlugin",
    "GuardResult",
    "HookContext",
    "HookRegistry",
    "PluginInfo",
    "PluginLoadError",
    "PluginManager",
    "RedactResult",
    "RedactionHookContext",
    "RedactorPlugin",
    "ViolationHookContext",
    "on_post_call",
    "on_pre_call",
    "on_redaction",
    "on_violation",
]

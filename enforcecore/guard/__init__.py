# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Resource limits, sandboxing, and kill switch.

Public API:

* :class:`CostTracker` — thread-safe cumulative cost tracking.
* :class:`KillSwitch` — coordinated hard termination on limit breach.
* :class:`ResourceGuard` — wraps execution with time/memory limits.
"""

from enforcecore.guard.engine import CostTracker, KillSwitch, ResourceGuard

__all__ = [
    "CostTracker",
    "KillSwitch",
    "ResourceGuard",
]

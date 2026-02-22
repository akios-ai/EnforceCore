# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Shared utility functions used across EnforceCore modules."""

from __future__ import annotations

from typing import Any


def extract_strings(values: tuple[Any, ...], *, _depth: int = 0) -> list[str]:
    """Recursively extract string values from nested structures.

    Handles dicts, lists, tuples, and sets.  Stops at a max depth of 20
    to prevent infinite recursion on self-referencing structures.

    Args:
        values: Tuple of values to inspect.
        _depth: Current recursion depth (internal).

    Returns:
        List of extracted string values.
    """
    if _depth > 20:
        return []

    result: list[str] = []
    for v in values:
        if isinstance(v, str):
            result.append(v)
        elif isinstance(v, dict):
            result.extend(extract_strings(tuple(v.values()), _depth=_depth + 1))
        elif isinstance(v, (list, tuple, set)):
            result.extend(extract_strings(tuple(v), _depth=_depth + 1))
    return result

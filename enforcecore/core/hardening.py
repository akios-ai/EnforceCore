"""Security hardening utilities for EnforceCore.

Provides input validation, nested data-structure redaction, enforcement-scope
tracking (via ``contextvars``), input-size checks, and dev-mode gating.

All functions are **fail-closed** — validation failures raise exceptions that
inherit from ``EnforceCoreError``.

.. versionadded:: 1.0.6
"""

from __future__ import annotations

import contextvars
import os
import re
import warnings
from typing import TYPE_CHECKING, Any

import structlog

from enforcecore.core.types import EnforceCoreError

if TYPE_CHECKING:
    from enforcecore.redactor.engine import RedactionResult

logger = structlog.get_logger("enforcecore.hardening")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_TOOL_NAME_LENGTH: int = 256
"""Maximum allowed length for a tool name."""

MAX_INPUT_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
"""Default maximum input payload size (sum of string/bytes args)."""

MAX_ENFORCEMENT_DEPTH: int = 10
"""Maximum nested enforcement depth before raising ``EnforcementDepthError``."""

_TOOL_NAME_RE = re.compile(r"^[\w.\-:<>]+$")
"""Pattern for valid tool names — word chars, dots, hyphens, colons, angle brackets."""


# ---------------------------------------------------------------------------
# Hardening exceptions
# ---------------------------------------------------------------------------


class HardeningError(EnforceCoreError):
    """Base class for all hardening-related errors."""


class InvalidToolNameError(HardeningError):
    """Tool name failed validation."""


class InputTooLargeError(HardeningError):
    """Input payload exceeds the configured maximum size."""


class EnforcementDepthError(HardeningError):
    """Enforcement nesting exceeds the maximum allowed depth."""


# ---------------------------------------------------------------------------
# Tool-name validation
# ---------------------------------------------------------------------------


def validate_tool_name(name: str) -> str:
    """Validate and normalize a tool name.

    Checks:
    - Non-empty after stripping whitespace.
    - Length does not exceed :data:`MAX_TOOL_NAME_LENGTH`.
    - Contains only word characters (``\\w``), dots, hyphens, and colons.

    Args:
        name: The raw tool name.

    Returns:
        The stripped, validated name.

    Raises:
        InvalidToolNameError: If validation fails.
    """
    stripped = name.strip()
    if not stripped:
        raise InvalidToolNameError("Tool name must not be empty")
    if len(stripped) > MAX_TOOL_NAME_LENGTH:
        raise InvalidToolNameError(
            f"Tool name exceeds maximum length ({len(stripped)} > {MAX_TOOL_NAME_LENGTH})"
        )
    if not _TOOL_NAME_RE.match(stripped):
        raise InvalidToolNameError(
            f"Tool name contains invalid characters: {stripped!r}. "
            "Only word characters, dots, hyphens, colons, and angle brackets are allowed."
        )
    return stripped


# ---------------------------------------------------------------------------
# Input-size checking
# ---------------------------------------------------------------------------


def check_input_size(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    max_bytes: int = MAX_INPUT_SIZE_BYTES,
) -> int:
    """Check that the combined size of string/bytes arguments is within limits.

    Only counts direct ``str`` and ``bytes`` values in *args* and *kwargs*.

    Args:
        args: Positional arguments.
        kwargs: Keyword arguments.
        max_bytes: Maximum allowed total size in bytes.

    Returns:
        The measured size in bytes.

    Raises:
        InputTooLargeError: If the total exceeds *max_bytes*.
    """
    total = 0
    for a in args:
        if isinstance(a, str):
            total += len(a.encode("utf-8"))
        elif isinstance(a, bytes):
            total += len(a)
    for v in kwargs.values():
        if isinstance(v, str):
            total += len(v.encode("utf-8"))
        elif isinstance(v, bytes):
            total += len(v)
    if total > max_bytes:
        raise InputTooLargeError(
            f"Input size ({total:,} bytes) exceeds limit ({max_bytes:,} bytes)"
        )
    return total


# ---------------------------------------------------------------------------
# Deep (recursive) redaction
# ---------------------------------------------------------------------------


def deep_redact(
    value: Any,
    redact_fn: Any,
    *,
    max_depth: int = 10,
    _depth: int = 0,
) -> tuple[Any, int]:
    """Recursively redact PII from nested data structures.

    Traverses ``dict``, ``list``, ``tuple``, and ``set`` containers.
    Applies *redact_fn* to every ``str`` leaf.

    Args:
        value: The value to redact.
        redact_fn: A callable that takes a ``str`` and returns a
            :class:`~enforcecore.redactor.engine.RedactionResult`.
        max_depth: Maximum recursion depth (safety limit).

    Returns:
        ``(redacted_value, total_count)`` where *total_count* is the number
        of PII entities redacted across all leaves.
    """
    if _depth > max_depth:
        return value, 0

    if isinstance(value, str):
        result: RedactionResult = redact_fn(value)
        return result.text, result.count

    total = 0

    if isinstance(value, dict):
        new_dict: dict[Any, Any] = {}
        for k, v in value.items():
            new_v, count = deep_redact(v, redact_fn, max_depth=max_depth, _depth=_depth + 1)
            new_dict[k] = new_v
            total += count
        return new_dict, total

    if isinstance(value, list):
        new_list: list[Any] = []
        for item in value:
            new_item, count = deep_redact(item, redact_fn, max_depth=max_depth, _depth=_depth + 1)
            new_list.append(new_item)
            total += count
        return new_list, total

    if isinstance(value, tuple):
        items: list[Any] = []
        for item in value:
            new_item, count = deep_redact(item, redact_fn, max_depth=max_depth, _depth=_depth + 1)
            items.append(new_item)
            total += count
        return tuple(items), total

    if isinstance(value, set):
        new_set: set[Any] = set()
        for item in value:
            new_item, count = deep_redact(item, redact_fn, max_depth=max_depth, _depth=_depth + 1)
            new_set.add(new_item)
            total += count
        return new_set, total

    # Non-container, non-string — pass through unchanged
    return value, 0


# ---------------------------------------------------------------------------
# Enforcement scope (contextvars-based nesting tracker)
# ---------------------------------------------------------------------------


class _EnforcementState:
    """Internal state for tracking enforcement call depth and chain."""

    __slots__ = ("depth", "tool_chain")

    def __init__(self) -> None:
        self.depth: int = 0
        self.tool_chain: list[str] = []


_enforcement_scope: contextvars.ContextVar[_EnforcementState | None] = contextvars.ContextVar(
    "enforcement_scope",
    default=None,
)


def enter_enforcement(
    tool_name: str,
    *,
    max_depth: int = MAX_ENFORCEMENT_DEPTH,
) -> int:
    """Enter an enforcement scope (call this before enforcing a tool).

    Increments the nesting depth and appends *tool_name* to the call chain.
    If the depth exceeds *max_depth*, raises :class:`EnforcementDepthError`.

    Args:
        tool_name: Name of the tool being enforced.
        max_depth: Maximum allowed depth.

    Returns:
        The new depth.

    Raises:
        EnforcementDepthError: If nesting is too deep.
    """
    state = _enforcement_scope.get()
    if state is None:
        state = _EnforcementState()
        _enforcement_scope.set(state)

    state.depth += 1
    state.tool_chain.append(tool_name)

    if state.depth > max_depth:
        raise EnforcementDepthError(
            f"Enforcement nesting depth ({state.depth}) exceeds maximum ({max_depth}). "
            f"Call chain: {' -> '.join(state.tool_chain)}"
        )

    logger.debug(
        "enforcement_scope_entered",
        tool=tool_name,
        depth=state.depth,
        chain=state.tool_chain,
    )
    return state.depth


def exit_enforcement() -> None:
    """Exit an enforcement scope (call this after enforcing a tool).

    Decrements the depth and pops the last tool from the chain.
    When depth reaches zero, the scope is cleared.
    """
    state = _enforcement_scope.get()
    if state is None:
        return

    if state.tool_chain:
        state.tool_chain.pop()
    state.depth = max(0, state.depth - 1)

    if state.depth == 0:
        _enforcement_scope.set(None)


def get_enforcement_depth() -> int:
    """Get the current enforcement nesting depth (0 = top-level)."""
    state = _enforcement_scope.get()
    return state.depth if state else 0


def get_enforcement_chain() -> list[str]:
    """Get the current enforcement call chain as a list of tool names."""
    state = _enforcement_scope.get()
    return list(state.tool_chain) if state else []


# ---------------------------------------------------------------------------
# Dev-mode and fail-open gating
# ---------------------------------------------------------------------------


def is_dev_mode() -> bool:
    """Check if development mode is enabled.

    Development mode is activated by setting the environment variable
    ``ENFORCECORE_DEV_MODE`` to ``1``, ``true``, or ``yes``.

    Returns:
        ``True`` if dev mode is enabled.
    """
    return os.environ.get("ENFORCECORE_DEV_MODE", "").strip().lower() in ("1", "true", "yes")


def _warn_fail_open() -> None:
    """Emit a loud warning if ``fail_open`` is enabled.

    In production, ``fail_open`` should never be used because it allows
    enforcement bypass on internal errors.  If dev mode is not enabled,
    this emits a ``RuntimeWarning``.

    .. versionchanged:: 1.0.16
       Renamed from ``warn_fail_open`` to ``_warn_fail_open`` (internal API).
    """
    if not is_dev_mode():
        warnings.warn(
            "SECURITY WARNING: fail_open is enabled without ENFORCECORE_DEV_MODE=1. "
            "In production, fail_open allows complete enforcement bypass on internal errors. "
            "Set ENFORCECORE_DEV_MODE=1 to acknowledge this risk, or disable fail_open.",
            RuntimeWarning,
            stacklevel=3,
        )
    logger.warning(
        "fail_open_enabled",
        dev_mode=is_dev_mode(),
        message="Enforcement errors will fall through to unprotected execution",
    )

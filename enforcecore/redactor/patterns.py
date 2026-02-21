"""Custom PII pattern registry.

Allows users to register domain-specific regex patterns for PII detection
at runtime. Custom patterns are additive alongside the built-in patterns
in the Redactor.

Example::

    from enforcecore.redactor.patterns import PatternRegistry

    # Register an employee ID pattern
    PatternRegistry.register(
        "employee_id",
        r"EMP-\\d{6}",
        placeholder="<EMPLOYEE_ID>",
    )

    # Register with a validator function
    PatternRegistry.register(
        "medical_record",
        r"MRN-\\d{8}",
        validator=lambda match: match.startswith("MRN-"),
    )

    # Now the Redactor will detect these alongside built-in PII categories.

Thread-safe: uses a lock for registry mutations.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from collections.abc import Callable

logger = structlog.get_logger("enforcecore.patterns")


# ---------------------------------------------------------------------------
# Custom pattern definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CustomPattern:
    """A user-defined PII detection pattern.

    Attributes:
        category: Unique category name (e.g., ``"employee_id"``).
        regex: Compiled regex pattern.
        placeholder: Replacement text for placeholder strategy
            (e.g., ``"<EMPLOYEE_ID>"``).
        mask: Replacement text for mask strategy (e.g., ``"***-******"``).
        validator: Optional callable that receives the matched text and
            returns True if it is a valid match. Use this to reduce
            false positives beyond what the regex can filter.
    """

    category: str
    regex: re.Pattern[str]
    placeholder: str = ""
    mask: str = ""
    validator: Callable[[str], bool] | None = None


# ---------------------------------------------------------------------------
# Pattern Registry
# ---------------------------------------------------------------------------

_global_patterns: dict[str, CustomPattern] = {}
_global_lock = threading.Lock()


class PatternRegistry:
    """Registry for user-defined PII detection patterns.

    Provides class-level methods for the global registry and instance
    methods for isolated registries (useful for testing).
    """

    __slots__ = ("_lock", "_patterns")

    def __init__(self) -> None:
        self._patterns: dict[str, CustomPattern] = {}
        self._lock = threading.Lock()

    # -- Global (class-level) API -------------------------------------------

    @classmethod
    def register(
        cls,
        category: str,
        pattern: str,
        *,
        placeholder: str = "",
        mask: str = "",
        validator: Callable[[str], bool] | None = None,
    ) -> None:
        """Register a custom PII pattern globally.

        Args:
            category: Unique name for this PII category.
            pattern: Regex pattern string.
            placeholder: Replacement for placeholder strategy. Defaults to
                ``<CATEGORY_UPPER>``.
            mask: Replacement for mask strategy. Defaults to asterisks.
            validator: Optional callable for post-match validation.

        Raises:
            ValueError: If category is empty or pattern is invalid regex.
        """
        if not category or not category.strip():
            msg = "Pattern category cannot be empty"
            raise ValueError(msg)

        try:
            compiled = re.compile(pattern)
        except re.error as e:
            msg = f"Invalid regex pattern for '{category}': {e}"
            raise ValueError(msg) from e

        resolved_placeholder = placeholder or f"<{category.upper()}>"
        resolved_mask = mask or ("*" * 8)

        custom = CustomPattern(
            category=category.strip(),
            regex=compiled,
            placeholder=resolved_placeholder,
            mask=resolved_mask,
            validator=validator,
        )

        with _global_lock:
            _global_patterns[custom.category] = custom

        logger.info("custom_pattern_registered", category=custom.category)

    @classmethod
    def unregister(cls, category: str) -> bool:
        """Remove a custom pattern by category name.

        Returns True if removed, False if not found.
        """
        with _global_lock:
            return _global_patterns.pop(category, None) is not None

    @classmethod
    def get(cls, category: str) -> CustomPattern | None:
        """Get a custom pattern by category name."""
        with _global_lock:
            return _global_patterns.get(category)

    @classmethod
    def get_all(cls) -> dict[str, CustomPattern]:
        """Return a copy of all registered custom patterns."""
        with _global_lock:
            return dict(_global_patterns)

    @classmethod
    def categories(cls) -> list[str]:
        """Return a list of all registered custom category names."""
        with _global_lock:
            return list(_global_patterns.keys())

    @classmethod
    def clear(cls) -> None:
        """Remove all custom patterns. Primarily for testing."""
        with _global_lock:
            _global_patterns.clear()

    @classmethod
    def count(cls) -> int:
        """Return the number of registered custom patterns."""
        with _global_lock:
            return len(_global_patterns)

    # -- Instance-level API (for isolated registries) -----------------------

    def add(
        self,
        category: str,
        pattern: str,
        *,
        placeholder: str = "",
        mask: str = "",
        validator: Callable[[str], bool] | None = None,
    ) -> None:
        """Register a pattern in this isolated registry."""
        if not category or not category.strip():
            msg = "Pattern category cannot be empty"
            raise ValueError(msg)

        try:
            compiled = re.compile(pattern)
        except re.error as e:
            msg = f"Invalid regex pattern for '{category}': {e}"
            raise ValueError(msg) from e

        custom = CustomPattern(
            category=category.strip(),
            regex=compiled,
            placeholder=placeholder or f"<{category.upper()}>",
            mask=mask or ("*" * 8),
            validator=validator,
        )

        with self._lock:
            self._patterns[custom.category] = custom

    def remove(self, category: str) -> bool:
        """Remove a pattern from this isolated registry."""
        with self._lock:
            return self._patterns.pop(category, None) is not None

    def get_patterns(self) -> dict[str, CustomPattern]:
        """Return a copy of patterns in this isolated registry."""
        with self._lock:
            return dict(self._patterns)

    def list_categories(self) -> list[str]:
        """Return category names in this isolated registry."""
        with self._lock:
            return list(self._patterns.keys())

    def clear_all(self) -> None:
        """Remove all patterns from this isolated registry."""
        with self._lock:
            self._patterns.clear()

    @property
    def pattern_count(self) -> int:
        """Number of patterns in this isolated registry."""
        with self._lock:
            return len(self._patterns)

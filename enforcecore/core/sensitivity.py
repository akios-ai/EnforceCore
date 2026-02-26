# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Sensitivity label enforcement for data flow control.

Provides lightweight Information Flow Control (IFC) between tool schemas and
their data fields.  Each field in a tool's arguments can carry a
:class:`~enforcecore.core.types.SensitivityLabel` annotation, and each tool
can declare a clearance level.  The :class:`SensitivityEnforcer` checks that
no field with a sensitivity label *higher* than the tool's clearance is sent
to that tool.

This is the first step toward full IFC as described in Sabelfeld et al.'s
trigger-action platform work — applied to AI agent tool calls.

**Flow rule:** ``field_sensitivity > tool_clearance`` → violation.

Levels (ascending): ``PUBLIC(0) < INTERNAL(1) < CONFIDENTIAL(2) < RESTRICTED(3)``

Example::

    from enforcecore.core.sensitivity import SensitivityEnforcer
    from enforcecore.core.types import SensitivityLabel

    enforcer = SensitivityEnforcer(
        tool_clearance=SensitivityLabel.INTERNAL,
        field_labels={
            "to": SensitivityLabel.PUBLIC,
            "subject": SensitivityLabel.INTERNAL,
            "body": SensitivityLabel.CONFIDENTIAL,  # ← exceeds clearance!
        },
    )
    violations = enforcer.check()
    # → [SensitivityViolation(field="body", label=CONFIDENTIAL, clearance=INTERNAL)]

.. versionadded:: 1.4.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from enforcecore.core.types import (
    SensitivityLabel,
    SensitivityViolationError,
    sensitivity_level,
)

logger = structlog.get_logger("enforcecore.sensitivity")

# ---------------------------------------------------------------------------
# Violation record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SensitivityViolation:
    """A single sensitivity flow violation detected by :class:`SensitivityEnforcer`.

    .. versionadded:: 1.4.0
    """

    field_name: str
    """The name of the field whose sensitivity label exceeds the clearance."""

    field_sensitivity: SensitivityLabel
    """The sensitivity label of the offending field."""

    tool_clearance: SensitivityLabel
    """The clearance level of the tool."""

    def __str__(self) -> str:
        return (
            f"field '{self.field_name}' sensitivity '{self.field_sensitivity.value}' "
            f"exceeds tool clearance '{self.tool_clearance.value}'"
        )


# ---------------------------------------------------------------------------
# Sensitivity enforcer
# ---------------------------------------------------------------------------


class SensitivityEnforcer:
    """Check data-flow constraints between field sensitivity labels and a
    tool's clearance level.

    This class is **stateless** after construction and safe to call
    concurrently.

    Args:
        tool_clearance: The maximum sensitivity level this tool may receive.
        field_labels: Mapping of field name → :class:`SensitivityLabel`.
            Fields that are not in the map are treated as
            :attr:`~SensitivityLabel.PUBLIC`.
        default_field_sensitivity: Sensitivity assigned to un-annotated fields.
            Defaults to ``PUBLIC`` (permissive).  Set to ``INTERNAL`` or higher
            to enforce a *deny-by-default* posture.

    Example::

        enforcer = SensitivityEnforcer(
            tool_clearance=SensitivityLabel.INTERNAL,
            field_labels={"api_key": SensitivityLabel.RESTRICTED},
        )
        violations = enforcer.check()
        enforcer.raise_if_violated(
            violations, tool_name="send_request", policy_name="prod"
        )

    .. versionadded:: 1.4.0
    """

    __slots__ = ("_default_sensitivity", "_field_labels", "_tool_clearance")

    def __init__(
        self,
        tool_clearance: SensitivityLabel | str,
        field_labels: dict[str, SensitivityLabel | str] | None = None,
        *,
        default_field_sensitivity: SensitivityLabel | str = SensitivityLabel.PUBLIC,
    ) -> None:
        self._tool_clearance = _coerce_label(tool_clearance)
        self._field_labels: dict[str, SensitivityLabel] = (
            {k: _coerce_label(v) for k, v in field_labels.items()} if field_labels else {}
        )
        self._default_sensitivity = _coerce_label(default_field_sensitivity)

    # -- Core check ----------------------------------------------------------

    def check(self) -> list[SensitivityViolation]:
        """Return all sensitivity violations (fields whose sensitivity exceeds
        the tool clearance).

        Returns an empty list if there are no violations.
        """
        violations: list[SensitivityViolation] = []
        clearance_level = sensitivity_level(self._tool_clearance)

        for field_name, label in self._field_labels.items():
            if sensitivity_level(label) > clearance_level:
                violations.append(
                    SensitivityViolation(
                        field_name=field_name,
                        field_sensitivity=label,
                        tool_clearance=self._tool_clearance,
                    )
                )
                logger.warning(
                    "sensitivity_violation_detected",
                    field=field_name,
                    field_sensitivity=label.value,
                    tool_clearance=self._tool_clearance.value,
                )

        return violations

    def check_kwargs(
        self,
        kwargs: dict[str, Any],
        *,
        override_labels: dict[str, SensitivityLabel | str] | None = None,
    ) -> list[SensitivityViolation]:
        """Check the sensitivity of *kwargs* field values against the clearance.

        Only fields present in *kwargs* are checked.  Field labels come from
        (in priority order): *override_labels*, then the instance's
        *field_labels*, then *default_field_sensitivity*.

        Args:
            kwargs: The keyword arguments about to be passed to the tool.
            override_labels: Per-call label overrides (highest priority).

        Returns:
            List of :class:`SensitivityViolation` for any field that exceeds
            the tool clearance.
        """
        violations: list[SensitivityViolation] = []
        clearance_level = sensitivity_level(self._tool_clearance)

        merged_labels: dict[str, SensitivityLabel] = dict(self._field_labels)
        if override_labels:
            merged_labels.update({k: _coerce_label(v) for k, v in override_labels.items()})

        for field_name in kwargs:
            label = merged_labels.get(field_name, self._default_sensitivity)
            if sensitivity_level(label) > clearance_level:
                violations.append(
                    SensitivityViolation(
                        field_name=field_name,
                        field_sensitivity=label,
                        tool_clearance=self._tool_clearance,
                    )
                )
                logger.warning(
                    "sensitivity_violation_detected",
                    field=field_name,
                    field_sensitivity=label.value,
                    tool_clearance=self._tool_clearance.value,
                )

        return violations

    def raise_if_violated(
        self,
        violations: list[SensitivityViolation],
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Raise :class:`~enforcecore.core.types.SensitivityViolationError` if
        *violations* is non-empty.

        Args:
            violations: Output from :meth:`check` or :meth:`check_kwargs`.
            tool_name: Name of the tool being enforced.
            policy_name: Name of the active policy.

        Raises:
            SensitivityViolationError: If any violation is present.
        """
        if not violations:
            return
        first = violations[0]
        details = "; ".join(str(v) for v in violations)
        raise SensitivityViolationError(
            f"Sensitivity violation in tool '{tool_name}': {details}",
            tool_name=tool_name,
            policy_name=policy_name,
            field_name=first.field_name,
            field_sensitivity=first.field_sensitivity.value,
            tool_clearance=first.tool_clearance.value,
        )

    # -- Properties ----------------------------------------------------------

    @property
    def tool_clearance(self) -> SensitivityLabel:
        """The tool's clearance level."""
        return self._tool_clearance

    @property
    def field_labels(self) -> dict[str, SensitivityLabel]:
        """A copy of the field → label mapping."""
        return dict(self._field_labels)

    def __repr__(self) -> str:
        return (
            f"SensitivityEnforcer("
            f"tool_clearance={self._tool_clearance.value!r}, "
            f"fields={list(self._field_labels.keys())})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_label(value: SensitivityLabel | str) -> SensitivityLabel:
    """Coerce a string or :class:`SensitivityLabel` to a :class:`SensitivityLabel`.

    Raises:
        ValueError: If *value* is not a valid sensitivity label.
    """
    if isinstance(value, SensitivityLabel):
        return value
    try:
        return SensitivityLabel(str(value).lower())
    except ValueError:
        valid = [m.value for m in SensitivityLabel]
        msg = f"Invalid sensitivity label {value!r}. Valid values: {valid}"
        raise ValueError(msg) from None


def check_tool_schema_sensitivity(
    tool_schema: dict[str, Any],
    policy_clearance: SensitivityLabel | str,
) -> list[SensitivityViolation]:
    """Convenience function: check a tool schema dict for sensitivity violations.

    The schema format follows the roadmap design::

        tool_schema = {
            "name": "send_email",
            "clearance": "public",
            "parameters": {
                "to":      {"type": "string", "sensitivity": "low"},
                "subject": {"type": "string", "sensitivity": "low"},
                "body":    {"type": "string", "sensitivity": "high"},
            },
        }

    The effective clearance is ``min(schema["clearance"], policy_clearance)``.
    Field sensitivity values ``"low"``/``"medium"``/``"high"`` are mapped to
    ``PUBLIC``/``INTERNAL``/``CONFIDENTIAL`` respectively for backwards
    compatibility with informal notation.

    Args:
        tool_schema: A dict with optional ``"clearance"`` key and
            ``"parameters"`` dict whose values may carry a ``"sensitivity"``
            key.
        policy_clearance: The policy-level clearance override (takes the
            *lower* of schema and policy clearances).

    Returns:
        List of :class:`SensitivityViolation` for fields whose sensitivity
        exceeds the effective clearance.

    .. versionadded:: 1.4.0
    """
    # Determine effective clearance (lower of schema clearance + policy clearance)
    schema_clearance_raw = tool_schema.get("clearance", "internal")
    schema_clearance = _coerce_label_with_aliases(str(schema_clearance_raw))
    effective_clearance_raw = policy_clearance
    effective_clearance = _coerce_label(effective_clearance_raw)

    # Take the lower clearance (more restrictive)
    if sensitivity_level(schema_clearance) < sensitivity_level(effective_clearance):
        effective_clearance = schema_clearance

    # Build field label map
    params = tool_schema.get("parameters", {})
    field_labels: dict[str, SensitivityLabel | str] = {}
    for field_name, field_def in params.items():
        if isinstance(field_def, dict) and "sensitivity" in field_def:
            field_labels[field_name] = _coerce_label_with_aliases(str(field_def["sensitivity"]))

    enforcer = SensitivityEnforcer(
        tool_clearance=effective_clearance,
        field_labels=field_labels,
    )
    return enforcer.check()


def _coerce_label_with_aliases(value: str) -> SensitivityLabel:
    """Coerce a string to SensitivityLabel, supporting common aliases.

    Aliases:
        ``low``  → ``PUBLIC``
        ``medium`` → ``INTERNAL``
        ``high`` → ``CONFIDENTIAL``
        ``critical`` → ``RESTRICTED``
    """
    _aliases: dict[str, SensitivityLabel] = {
        "low": SensitivityLabel.PUBLIC,
        "medium": SensitivityLabel.INTERNAL,
        "high": SensitivityLabel.CONFIDENTIAL,
        "critical": SensitivityLabel.RESTRICTED,
    }
    normalised = value.lower().strip()
    if normalised in _aliases:
        return _aliases[normalised]
    return _coerce_label(normalised)

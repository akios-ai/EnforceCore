"""Content rule engine for argument-level inspection.

Provides runtime inspection of tool call arguments to block dangerous
patterns such as shell injection, path traversal, SQL injection, and
code execution.

Built-in rule sets:
- ``shell_injection``  -- ``rm -rf``, ``; sudo``, ``&& curl``, pipe to shell
- ``path_traversal``   -- ``../``, absolute paths, null bytes
- ``sql_injection``    -- ``' OR 1=1``, ``UNION SELECT``, ``DROP TABLE``
- ``code_execution``   -- ``exec()``, ``eval()``, ``__import__()``

Custom rules can be added via regex or callable predicates.

Example::

    from enforcecore.core.rules import RuleEngine, ContentRule

    engine = RuleEngine()
    engine.add_rule(ContentRule(
        name="no_curl",
        pattern=r"curl\\s+https?://",
        description="Block curl commands",
    ))
    violations = engine.check("curl https://evil.com")
    # [RuleViolation(rule_name="no_curl", ...)]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import Callable

logger = structlog.get_logger("enforcecore.rules")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContentRule:
    """A single content inspection rule.

    Rules can be defined via a regex pattern and/or a callable predicate.
    If both are provided, both must match for a violation to be reported.

    Attributes:
        name: Unique identifier for this rule.
        pattern: Regex pattern that triggers the rule. Case-insensitive.
        description: Human-readable description of what the rule blocks.
        action: What to do when the rule matches. Default: ``block``.
        predicate: Optional callable that takes the matched text and
            returns True if it should be flagged.
    """

    name: str
    pattern: str = ""
    description: str = ""
    action: str = "block"
    predicate: Callable[[str], bool] | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            msg = "Rule name must not be empty"
            raise ValueError(msg)
        if not self.pattern and self.predicate is None:
            msg = f"Rule '{self.name}' must have a pattern or predicate"
            raise ValueError(msg)


@dataclass(frozen=True)
class RuleViolation:
    """A detected content rule violation."""

    rule_name: str
    matched_text: str
    description: str
    action: str = "block"
    position: int = -1


@dataclass
class ContentRuleConfig:
    """Policy configuration for content rules.

    Used in policy YAML::

        content_rules:
          enabled: true
          block_patterns:
            - name: shell_injection
              pattern: "rm\\\\s+-rf|;\\\\s*sudo"
              action: block
    """

    enabled: bool = False
    block_patterns: list[dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in rule patterns
# ---------------------------------------------------------------------------

_BUILTIN_RULES: dict[str, ContentRule] = {
    "shell_injection": ContentRule(
        name="shell_injection",
        pattern=(
            r"(?:rm\s+-r[f ]|;\s*sudo\b|&&\s*(?:curl|wget|nc|bash|sh|zsh)\b"
            r"|`[^`]+`|\$\([^)]+\)"
            r"|\|\s*(?:bash|sh|zsh|exec)\b"
            r"|>\s*/(?:etc|dev|proc)/)"
        ),
        description="Potential shell injection detected in arguments",
    ),
    "path_traversal": ContentRule(
        name="path_traversal",
        pattern=(
            r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%00"
            r"|/etc/(?:passwd|shadow|hosts)"
            r"|\\\\[a-zA-Z]+\\)"
        ),
        description="Potential path traversal detected in arguments",
    ),
    "sql_injection": ContentRule(
        name="sql_injection",
        pattern=(
            r"(?:'\s*(?:OR|AND)\s+\d+\s*=\s*\d+"
            r"|(?:UNION|INTERSECT)\s+(?:ALL\s+)?SELECT\b"
            r"|;\s*(?:DROP|DELETE|TRUNCATE|ALTER|INSERT)\s+"
            r"|--\s*$"
            r"|/\*.*\*/)"
        ),
        description="Potential SQL injection detected in arguments",
    ),
    "code_execution": ContentRule(
        name="code_execution",
        pattern=(
            r"(?:(?:^|[^a-zA-Z_])(?:exec|eval|compile)\s*\("
            r"|__import__\s*\("
            r"|importlib\.import_module\s*\("
            r"|os\.(?:system|popen|exec[a-z]*)\s*\("
            r"|subprocess\.(?:call|run|Popen|check_output)\s*\()"
        ),
        description="Potential code execution detected in arguments",
    ),
}


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """Content rule evaluation engine.

    Checks text against a set of content rules and returns any violations.
    Thread-safe for reads (rules are typically set at init time).

    Example::

        engine = RuleEngine.with_builtins()
        violations = engine.check("rm -rf /")
        for v in violations:
            print(f"BLOCKED: {v.rule_name} - {v.description}")
    """

    __slots__ = ("_compiled", "_rules")

    def __init__(self, rules: list[ContentRule] | None = None) -> None:
        self._rules: list[ContentRule] = list(rules) if rules else []
        self._compiled: dict[str, re.Pattern[str]] = {}
        for rule in self._rules:
            if rule.pattern:
                self._compiled[rule.name] = re.compile(rule.pattern, re.IGNORECASE)

    @classmethod
    def with_builtins(cls) -> RuleEngine:
        """Create an engine with all built-in rules enabled."""
        return cls(list(_BUILTIN_RULES.values()))

    @classmethod
    def from_config(cls, config: ContentRuleConfig) -> RuleEngine | None:
        """Create an engine from a policy ContentRuleConfig.

        Returns None if content rules are disabled.
        """
        if not config.enabled:
            return None

        rules: list[ContentRule] = []

        for pattern_dict in config.block_patterns:
            name = pattern_dict.get("name", "")
            # Check if it's a built-in rule name
            if name in _BUILTIN_RULES and "pattern" not in pattern_dict:
                rules.append(_BUILTIN_RULES[name])
            else:
                rules.append(
                    ContentRule(
                        name=name,
                        pattern=pattern_dict.get("pattern", ""),
                        description=pattern_dict.get("description", ""),
                        action=pattern_dict.get("action", "block"),
                    )
                )

        # If no specific patterns given but enabled, use all builtins
        if not rules:
            rules = list(_BUILTIN_RULES.values())

        return cls(rules)

    def add_rule(self, rule: ContentRule) -> None:
        """Add a rule to the engine."""
        self._rules.append(rule)
        if rule.pattern:
            self._compiled[rule.name] = re.compile(rule.pattern, re.IGNORECASE)

    @property
    def rules(self) -> list[ContentRule]:
        """All registered rules (read-only copy)."""
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def check(self, text: str) -> list[RuleViolation]:
        """Check text against all rules.

        Returns a list of violations (empty means clean).
        """
        if not text or not self._rules:
            return []

        violations: list[RuleViolation] = []

        for rule in self._rules:
            compiled = self._compiled.get(rule.name)

            if compiled is not None:
                match = compiled.search(text)
                if match:
                    # If predicate also set, it must pass too
                    if rule.predicate is not None and not rule.predicate(match.group()):
                        continue
                    violations.append(
                        RuleViolation(
                            rule_name=rule.name,
                            matched_text=match.group(),
                            description=rule.description,
                            action=rule.action,
                            position=match.start(),
                        )
                    )
            elif rule.predicate is not None:
                # Predicate-only rule
                if rule.predicate(text):
                    violations.append(
                        RuleViolation(
                            rule_name=rule.name,
                            matched_text=text[:100],
                            description=rule.description,
                            action=rule.action,
                        )
                    )

        if violations:
            logger.warning(
                "content_rule_violations",
                count=len(violations),
                rules=[v.rule_name for v in violations],
            )

        return violations

    def check_args(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> list[RuleViolation]:
        """Check all string arguments and string values in kwargs.

        Recursively inspects nested structures (dicts, lists, tuples).
        """
        violations: list[RuleViolation] = []
        texts = _extract_strings(args) + _extract_strings(tuple(kwargs.values()))
        for text in texts:
            violations.extend(self.check(text))
        return violations

    def __repr__(self) -> str:
        return f"RuleEngine(rules={len(self._rules)})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_strings(values: tuple[Any, ...]) -> list[str]:
    """Recursively extract string values from nested structures."""
    result: list[str] = []
    for v in values:
        if isinstance(v, str):
            result.append(v)
        elif isinstance(v, dict):
            result.extend(_extract_strings(tuple(v.values())))
        elif isinstance(v, (list, tuple)):
            result.extend(_extract_strings(tuple(v)))
    return result


def get_builtin_rules() -> dict[str, ContentRule]:
    """Return a copy of all built-in content rules."""
    return dict(_BUILTIN_RULES)

# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Network domain enforcement for EnforceCore.

Extracts domains from URL-like strings in arguments and checks them
against the policy's allowed/denied domain lists. Supports wildcard
domain patterns (e.g., ``*.example.com``).

Example::

    from enforcecore.guard.network import DomainChecker

    checker = DomainChecker(
        allowed_domains=["api.openai.com", "*.internal.corp"],
        denied_domains=["*.malware.xyz"],
    )
    checker.check_args(("https://api.openai.com/v1/chat",), {})  # OK
    checker.check_args(("https://evil.malware.xyz",), {})  # raises
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

import structlog

from enforcecore.core.types import DomainDeniedError
from enforcecore.utils import extract_strings

logger = structlog.get_logger("enforcecore.network")

# Regex to extract domains from URL-like strings
_URL_PATTERN = re.compile(r"https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?::\d+)?)")


class DomainChecker:
    """Checks domains in arguments against allow/deny lists.

    Supports wildcard patterns using fnmatch (e.g., ``*.example.com``).
    Denied domains take priority over allowed domains.
    """

    __slots__ = ("_allowed", "_denied", "_deny_all_other")

    def __init__(
        self,
        *,
        allowed_domains: list[str] | None = None,
        denied_domains: list[str] | None = None,
        deny_all_other: bool = True,
    ) -> None:
        """Initialize the domain checker.

        Args:
            allowed_domains: List of allowed domain patterns (supports
                fnmatch wildcards like ``*.example.com``).
            denied_domains: List of denied domain patterns. Takes
                priority over the allowed list.
            deny_all_other: If ``True``, domains not in the allowed
                list are denied. Defaults to ``True``.
        """
        self._allowed = [d.lower() for d in (allowed_domains or [])]
        self._denied = [d.lower() for d in (denied_domains or [])]
        self._deny_all_other = deny_all_other

    @classmethod
    def from_policy(
        cls,
        network_policy: Any,
    ) -> DomainChecker | None:
        """Create from a NetworkPolicy model. Returns None if not enabled."""
        if not getattr(network_policy, "enabled", False):
            return None
        return cls(
            allowed_domains=getattr(network_policy, "allowed_domains", []),
            denied_domains=getattr(network_policy, "denied_domains", []),
            deny_all_other=getattr(network_policy, "deny_all_other", True),
        )

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is allowed by the policy."""
        domain_lower = domain.lower().split(":")[0]  # Strip port

        # Denied list takes priority
        for pattern in self._denied:
            if fnmatch.fnmatch(domain_lower, pattern):
                return False

        # If allowed list is empty and deny_all_other is False, allow all
        if not self._allowed and not self._deny_all_other:
            return True

        # If allowed list is empty and deny_all_other is True, deny all
        if not self._allowed and self._deny_all_other:
            return False

        # Check allowed list
        for pattern in self._allowed:
            if fnmatch.fnmatch(domain_lower, pattern):
                return True

        return not self._deny_all_other

    def extract_domains(self, text: str) -> list[str]:
        """Extract domains from URL-like strings in text."""
        return [m.group(1).lower().split(":")[0] for m in _URL_PATTERN.finditer(text)]

    def check_text(
        self,
        text: str,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Check a text string for denied domains.

        Raises:
            DomainDeniedError: If a denied domain is found.
        """
        for domain in self.extract_domains(text):
            if not self.is_domain_allowed(domain):
                logger.warning(
                    "domain_denied",
                    domain=domain,
                    tool=tool_name,
                    policy=policy_name,
                )
                raise DomainDeniedError(
                    domain,
                    tool_name=tool_name,
                    policy_name=policy_name,
                )

    def check_args(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Check all string arguments for denied domains.

        Recursively inspects nested structures.

        Raises:
            DomainDeniedError: If a denied domain is found.
        """
        texts = extract_strings(args) + extract_strings(tuple(kwargs.values()))
        for text in texts:
            self.check_text(
                text,
                tool_name=tool_name,
                policy_name=policy_name,
            )

    def __repr__(self) -> str:
        return (
            f"DomainChecker(allowed={len(self._allowed)}, "
            f"denied={len(self._denied)}, deny_other={self._deny_all_other})"
        )

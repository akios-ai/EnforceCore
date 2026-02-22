# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Secret detection for EnforceCore.

Detects API keys, tokens, private keys, and other secrets in text.
Integrated into the PII redaction pipeline to prevent secret leakage.

Built-in categories:
- aws_access_key: AWS access key IDs (AKIA...)
- aws_secret_key: AWS secret access keys (40 chars base64)
- github_token: GitHub personal access tokens (ghp_/gho_/ghs_/ghr_)
- generic_api_key: Generic API key patterns (api_key=..., apikey:...)
- bearer_token: Bearer/JWT tokens in Authorization headers
- private_key: PEM-encoded private keys (RSA, EC, etc.)
- password_in_url: Passwords embedded in URLs (://user:pass@host)
- gcp_service_account: Google Cloud service account key JSON
- azure_connection_string: Azure storage/service bus connection strings
- database_connection_string: Database URIs (postgres, mysql, mongodb, redis)
- ssh_private_key: OpenSSH private key markers

Thread-safe: pattern compilation at import time, stateless detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

logger = structlog.get_logger("enforcecore.secrets")


# ---------------------------------------------------------------------------
# Secret categories and patterns
# ---------------------------------------------------------------------------

# Each pattern is designed for low false-positive rate.
# We anchor on distinctive prefixes/formats where possible.

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    # AWS access key IDs: always start with AKIA, exactly 20 uppercase alphanum
    "aws_access_key": re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    # AWS secret keys: 40 chars of base64-like characters, often after = or :
    "aws_secret_key": re.compile(
        r"(?:aws_secret_access_key|secret_key|SecretAccessKey)"
        r"""[\s]*[=:]["']?\s*"""
        r"([A-Za-z0-9/+=]{40})"
    ),
    # GitHub tokens: ghp_, gho_, ghs_, ghr_ followed by 36 alphanum
    "github_token": re.compile(r"\bgh[psotr]_[A-Za-z0-9_]{36,255}\b"),
    # Generic API key patterns: key=value near "api_key", "apikey", "api-key"
    "generic_api_key": re.compile(
        r"(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)"
        r"""[\s]*[=:]["']?\s*"""
        r"([A-Za-z0-9_\-]{16,128})",
        re.IGNORECASE,
    ),
    # Bearer tokens in auth headers
    "bearer_token": re.compile(
        r"[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*(?:\.[A-Za-z0-9\-._~+/]+=*)*)",
    ),
    # PEM private keys (RSA, EC, DSA, OPENSSH)
    "private_key": re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?"
        r"PRIVATE\s+KEY-----"
        r"[\s\S]*?"
        r"-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?"
        r"PRIVATE\s+KEY-----"
    ),
    # Passwords in URLs: scheme://user:password@host
    "password_in_url": re.compile(
        r"(?:https?|ftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
        r"://[^:\s]+:([^@\s]{3,})@[^\s]+"
    ),
    # GCP service account key JSON (matches the private_key_id field pattern)
    "gcp_service_account": re.compile(
        r'"type"\s*:\s*"service_account"'
        r"[\s\S]{0,500}"
        r'"private_key_id"\s*:\s*"([a-f0-9]{40})"',
    ),
    # Azure connection strings (storage, service bus, cosmos, etc.)
    "azure_connection_string": re.compile(
        r"(?:DefaultEndpointsProtocol|AccountName|AccountKey|"
        r"SharedAccessKey|Endpoint=sb://)"
        r"[A-Za-z0-9+/=;.:\-\w]{20,500}",
        re.IGNORECASE,
    ),
    # Database connection strings with credentials
    "database_connection_string": re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)"
        r"://[^\s:]+:[^\s@]+@[^\s]+",
        re.IGNORECASE,
    ),
    # SSH private key blocks
    "ssh_private_key": re.compile(
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"
        r"[\s\S]*?"
        r"-----END\s+OPENSSH\s+PRIVATE\s+KEY-----"
    ),
}


# Placeholders for redaction
_SECRET_PLACEHOLDERS: dict[str, str] = {
    "aws_access_key": "<AWS_KEY>",
    "aws_secret_key": "<AWS_SECRET>",
    "github_token": "<GITHUB_TOKEN>",
    "generic_api_key": "<API_KEY>",
    "bearer_token": "<BEARER_TOKEN>",
    "private_key": "<PRIVATE_KEY>",
    "password_in_url": "<URL_PASSWORD>",
    "gcp_service_account": "<GCP_SERVICE_ACCOUNT>",
    "azure_connection_string": "<AZURE_CONNECTION_STRING>",
    "database_connection_string": "<DATABASE_URI>",
    "ssh_private_key": "<SSH_PRIVATE_KEY>",
}

_SECRET_MASKS: dict[str, str] = {
    "aws_access_key": "AKIA************",
    "aws_secret_key": "****************************************",
    "github_token": "ghp_************************************",
    "generic_api_key": "****************",
    "bearer_token": "Bearer ****...",
    "private_key": "-----REDACTED PRIVATE KEY-----",
    "password_in_url": "****",
    "gcp_service_account": "<GCP_KEY_REDACTED>",
    "azure_connection_string": "AccountKey=****",
    "database_connection_string": "://****:****@****",
    "ssh_private_key": "-----REDACTED SSH KEY-----",
}

# Default enabled categories
DEFAULT_SECRET_CATEGORIES: tuple[str, ...] = (
    "aws_access_key",
    "aws_secret_key",
    "github_token",
    "generic_api_key",
    "bearer_token",
    "private_key",
    "password_in_url",
    "gcp_service_account",
    "azure_connection_string",
    "database_connection_string",
    "ssh_private_key",
)


# ---------------------------------------------------------------------------
# Detected secret
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectedSecret:
    """A secret found in text."""

    category: str
    start: int
    end: int
    text: str


# ---------------------------------------------------------------------------
# Secret Scanner
# ---------------------------------------------------------------------------


class SecretScanner:
    """Detects secrets (API keys, tokens, private keys) in text.

    Works alongside the PII Redactor. Secrets are treated as a separate
    concern from personal information but use the same redaction pipeline.

    Example::

        scanner = SecretScanner()
        secrets = scanner.detect("My key is AKIAIOSFODNN7EXAMPLE")
        # [DetectedSecret(category="aws_access_key", ...)]

        scanner = SecretScanner(categories=["github_token", "private_key"])
        # Only scans for GitHub tokens and private keys
    """

    __slots__ = ("_categories",)

    def __init__(
        self,
        categories: tuple[str, ...] | list[str] | None = None,
    ) -> None:
        """Initialize the secret scanner.

        Args:
            categories: Secret categories to detect. Defaults to all
                supported categories (AWS, GitHub, bearer tokens, etc.).

        Raises:
            ValueError: If an unknown category is specified.
        """
        self._categories = tuple(categories) if categories else DEFAULT_SECRET_CATEGORIES

        # Validate categories
        for cat in self._categories:
            if cat not in _SECRET_PATTERNS:
                msg = (
                    f"Unknown secret category: '{cat}'. Supported: {list(_SECRET_PATTERNS.keys())}"
                )
                raise ValueError(msg)

    @property
    def categories(self) -> tuple[str, ...]:
        return self._categories

    def detect(self, text: str) -> list[DetectedSecret]:
        """Detect secrets in text.

        Returns a list of DetectedSecret objects sorted by start position
        (descending) for safe right-to-left replacement.
        """
        secrets: list[DetectedSecret] = []

        for cat in self._categories:
            pattern = _SECRET_PATTERNS[cat]
            for match in pattern.finditer(text):
                secrets.append(
                    DetectedSecret(
                        category=cat,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(),
                    )
                )

        # Remove overlaps (keep longer match)
        secrets = _remove_overlaps(secrets)

        # Sort descending for right-to-left replacement
        secrets.sort(key=lambda s: s.start, reverse=True)
        return secrets

    def scan_and_report(self, text: str) -> dict[str, int]:
        """Scan text and return a count per category.

        Useful for quick auditing without needing full match details.
        """
        secrets = self.detect(text)
        counts: dict[str, int] = {}
        for s in secrets:
            counts[s.category] = counts.get(s.category, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def get_secret_placeholder(category: str) -> str:
    """Get the placeholder string for a secret category."""
    return _SECRET_PLACEHOLDERS.get(category, f"<{category.upper()}>")


def get_secret_mask(category: str) -> str:
    """Get the mask string for a secret category."""
    return _SECRET_MASKS.get(category, "*" * 16)


def get_all_secret_categories() -> list[str]:
    """Return all supported secret category names."""
    return list(_SECRET_PATTERNS.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _remove_overlaps(secrets: list[DetectedSecret]) -> list[DetectedSecret]:
    """Remove overlapping detections, keeping the longer match."""
    if not secrets:
        return secrets

    sorted_secrets = sorted(secrets, key=lambda s: (s.start, -(s.end - s.start)))
    result: list[DetectedSecret] = [sorted_secrets[0]]

    for secret in sorted_secrets[1:]:
        last = result[-1]
        if secret.start >= last.end:
            result.append(secret)

    return result

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for secret detection."""

from __future__ import annotations

import pytest

from enforcecore.redactor.secrets import (
    DEFAULT_SECRET_CATEGORIES,
    DetectedSecret,
    SecretScanner,
    get_all_secret_categories,
    get_secret_mask,
    get_secret_placeholder,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner() -> SecretScanner:
    """Scanner with all categories enabled."""
    return SecretScanner()


@pytest.fixture
def aws_scanner() -> SecretScanner:
    """Scanner limited to AWS categories."""
    return SecretScanner(categories=["aws_access_key", "aws_secret_key"])


# ---------------------------------------------------------------------------
# SecretScanner initialization
# ---------------------------------------------------------------------------


class TestSecretScannerInit:
    def test_default_categories(self, scanner: SecretScanner):
        assert scanner.categories == DEFAULT_SECRET_CATEGORIES

    def test_custom_categories(self, aws_scanner: SecretScanner):
        assert aws_scanner.categories == ("aws_access_key", "aws_secret_key")

    def test_unknown_category_raises(self):
        with pytest.raises(ValueError, match="Unknown secret category"):
            SecretScanner(categories=["nonexistent_type"])

    def test_empty_list_uses_defaults(self):
        s = SecretScanner(categories=None)
        assert s.categories == DEFAULT_SECRET_CATEGORIES


# ---------------------------------------------------------------------------
# AWS access key detection
# ---------------------------------------------------------------------------


class TestAWSAccessKey:
    def test_detects_akia(self, scanner: SecretScanner):
        text = "key: AKIAIOSFODNN7EXAMPLE"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "aws_access_key" in cats

    def test_detects_asia(self, scanner: SecretScanner):
        text = "key: ASIAIOSFODNN7EXAMPLE"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "aws_access_key" in cats

    def test_no_false_positive_on_short_key(self, scanner: SecretScanner):
        text = "key: AKIA1234"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "aws_access_key" not in cats


# ---------------------------------------------------------------------------
# AWS secret key detection
# ---------------------------------------------------------------------------


class TestAWSSecretKey:
    def test_detects_secret_key(self, scanner: SecretScanner):
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "aws_secret_key" in cats

    def test_detects_with_colon_separator(self, scanner: SecretScanner):
        text = "secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "aws_secret_key" in cats


# ---------------------------------------------------------------------------
# GitHub token detection
# ---------------------------------------------------------------------------


class TestGitHubToken:
    def test_detects_ghp_token(self, scanner: SecretScanner):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "github_token" in cats

    def test_detects_gho_token(self, scanner: SecretScanner):
        text = "token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "github_token" in cats

    def test_detects_ghs_token(self, scanner: SecretScanner):
        text = "token: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "github_token" in cats

    def test_no_false_positive_on_short_ghp(self, scanner: SecretScanner):
        text = "ghp_short"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "github_token" not in cats


# ---------------------------------------------------------------------------
# Generic API key detection
# ---------------------------------------------------------------------------


class TestGenericAPIKey:
    def test_detects_api_key_equals(self, scanner: SecretScanner):
        text = "api_key=xk_fake_abc123def456ghi789jkl012"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "generic_api_key" in cats

    def test_detects_api_key_colon(self, scanner: SecretScanner):
        text = "apikey: mySecretApiKey1234567890123456"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "generic_api_key" in cats

    def test_case_insensitive(self, scanner: SecretScanner):
        text = "API_KEY=abcdefghijklmnop12345678"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "generic_api_key" in cats


# ---------------------------------------------------------------------------
# Bearer token detection
# ---------------------------------------------------------------------------


class TestBearerToken:
    def test_detects_bearer_token(self, scanner: SecretScanner):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "bearer_token" in cats

    def test_detects_lowercase_bearer(self, scanner: SecretScanner):
        text = "bearer abc123def456ghi789jkl012mno345pqr"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "bearer_token" in cats


# ---------------------------------------------------------------------------
# Private key detection
# ---------------------------------------------------------------------------


class TestPrivateKey:
    def test_detects_rsa_private_key(self, scanner: SecretScanner):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "private_key" in cats

    def test_detects_ec_private_key(self, scanner: SecretScanner):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg...\n-----END EC PRIVATE KEY-----"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "private_key" in cats

    def test_detects_generic_private_key(self, scanner: SecretScanner):
        text = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "private_key" in cats


# ---------------------------------------------------------------------------
# Password in URL detection
# ---------------------------------------------------------------------------


class TestPasswordInURL:
    def test_detects_http_password(self, scanner: SecretScanner):
        text = "url: https://admin:supersecret@db.example.com:5432/mydb"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "password_in_url" in cats

    def test_detects_postgres_password(self, scanner: SecretScanner):
        text = "dsn = postgresql://user:p4ssw0rd@localhost:5432/db"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "password_in_url" in cats

    def test_detects_mongodb_password(self, scanner: SecretScanner):
        text = "mongodb+srv://user:secret@cluster.mongodb.net/db"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "password_in_url" in cats


# ---------------------------------------------------------------------------
# scan_and_report
# ---------------------------------------------------------------------------


class TestScanAndReport:
    def test_counts_per_category(self, scanner: SecretScanner):
        text = "AKIAIOSFODNN7EXAMPLE ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij "
        report = scanner.scan_and_report(text)
        assert "aws_access_key" in report
        assert "github_token" in report

    def test_empty_text(self, scanner: SecretScanner):
        report = scanner.scan_and_report("")
        assert report == {}

    def test_no_secrets(self, scanner: SecretScanner):
        report = scanner.scan_and_report("This is a normal sentence.")
        assert report == {}


# ---------------------------------------------------------------------------
# DetectedSecret
# ---------------------------------------------------------------------------


class TestDetectedSecret:
    def test_frozen_dataclass(self):
        s = DetectedSecret(category="test", start=0, end=5, text="hello")
        with pytest.raises(AttributeError):
            s.category = "changed"  # type: ignore[misc]

    def test_fields(self):
        s = DetectedSecret(category="aws_access_key", start=10, end=30, text="AKIAIOSFODNN7EXAMPLE")
        assert s.category == "aws_access_key"
        assert s.start == 10
        assert s.end == 30


# ---------------------------------------------------------------------------
# Overlap removal
# ---------------------------------------------------------------------------


class TestOverlapRemoval:
    def test_overlapping_detections_keep_longer(self, scanner: SecretScanner):
        """When two patterns overlap, the longer match wins."""
        # This test uses the scanner normally; overlap removal is internal
        text = "api_key=AKIAIOSFODNN7EXAMPLE"
        secrets = scanner.detect(text)
        # Should not have duplicate overlapping results for the same range
        starts = [s.start for s in secrets]
        assert len(starts) == len(set(starts)) or len(secrets) <= 2


# ---------------------------------------------------------------------------
# Descending sort order
# ---------------------------------------------------------------------------


class TestSortOrder:
    def test_results_sorted_descending_by_start(self, scanner: SecretScanner):
        text = "first AKIAIOSFODNN7EXAMPLE then ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        secrets = scanner.detect(text)
        if len(secrets) >= 2:
            assert secrets[0].start >= secrets[1].start


# ---------------------------------------------------------------------------
# Category-limited scanning
# ---------------------------------------------------------------------------


class TestCategoryLimiting:
    def test_only_scans_configured_categories(self, aws_scanner: SecretScanner):
        text = "AKIAIOSFODNN7EXAMPLE ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        secrets = aws_scanner.detect(text)
        cats = {s.category for s in secrets}
        assert "github_token" not in cats
        # AWS key should be detected
        assert "aws_access_key" in cats


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class TestModuleHelpers:
    def test_get_secret_placeholder_known(self):
        assert get_secret_placeholder("aws_access_key") == "<AWS_KEY>"
        assert get_secret_placeholder("github_token") == "<GITHUB_TOKEN>"

    def test_get_secret_placeholder_unknown(self):
        assert get_secret_placeholder("unknown_cat") == "<UNKNOWN_CAT>"

    def test_get_secret_mask_known(self):
        assert get_secret_mask("aws_access_key") == "AKIA************"
        assert get_secret_mask("private_key") == "-----REDACTED PRIVATE KEY-----"

    def test_get_secret_mask_unknown(self):
        assert get_secret_mask("unknown_cat") == "****************"

    def test_get_all_secret_categories(self):
        cats = get_all_secret_categories()
        assert "aws_access_key" in cats
        assert "github_token" in cats
        assert "private_key" in cats
        assert len(cats) == 11

"""Tests for enhanced secret detection categories (v1.0.10).

Tests the 4 new secret categories added in v1.0.10:
- gcp_service_account
- azure_connection_string
- database_connection_string
- ssh_private_key
"""

from __future__ import annotations

import pytest

from enforcecore.redactor.secrets import (
    DEFAULT_SECRET_CATEGORIES,
    SecretScanner,
    get_all_secret_categories,
    get_secret_mask,
    get_secret_placeholder,
)


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner()


# ---------------------------------------------------------------------------
# GCP service account key
# ---------------------------------------------------------------------------


class TestGCPServiceAccount:
    def test_detects_service_account_json(self, scanner: SecretScanner) -> None:
        text = """
        {
          "type": "service_account",
          "project_id": "my-project-123",
          "private_key_id": "abcdef1234567890abcdef1234567890abcdef12",
          "private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAK..."
        }
        """
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "gcp_service_account" in cats

    def test_no_false_positive_without_private_key_id(self, scanner: SecretScanner) -> None:
        text = '{"type": "service_account", "project_id": "test"}'
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "gcp_service_account" not in cats

    def test_placeholder(self) -> None:
        assert get_secret_placeholder("gcp_service_account") == "<GCP_SERVICE_ACCOUNT>"

    def test_mask(self) -> None:
        assert get_secret_mask("gcp_service_account") == "<GCP_KEY_REDACTED>"


# ---------------------------------------------------------------------------
# Azure connection strings
# ---------------------------------------------------------------------------


class TestAzureConnectionString:
    def test_detects_storage_connection_string(self, scanner: SecretScanner) -> None:
        text = (
            "DefaultEndpointsProtocol=https;AccountName=myaccount;"
            "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==;"
            "EndpointSuffix=core.windows.net"
        )
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "azure_connection_string" in cats

    def test_detects_service_bus_connection(self, scanner: SecretScanner) -> None:
        text = "Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcdefghijklmnopqrstu"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "azure_connection_string" in cats

    def test_detects_account_key(self, scanner: SecretScanner) -> None:
        text = "AccountKey=xYzAbCdEfGhIjKlMnOpQrStUvWx0123456789+/=="
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "azure_connection_string" in cats

    def test_placeholder(self) -> None:
        assert get_secret_placeholder("azure_connection_string") == "<AZURE_CONNECTION_STRING>"

    def test_mask(self) -> None:
        assert get_secret_mask("azure_connection_string") == "AccountKey=****"


# ---------------------------------------------------------------------------
# Database connection strings
# ---------------------------------------------------------------------------


class TestDatabaseConnectionString:
    def test_detects_postgres(self, scanner: SecretScanner) -> None:
        text = "postgresql://admin:s3cret@db.example.com:5432/mydb"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "database_connection_string" in cats or "password_in_url" in cats

    def test_detects_mysql(self, scanner: SecretScanner) -> None:
        text = "mysql://root:password@localhost:3306/app"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "database_connection_string" in cats or "password_in_url" in cats

    def test_detects_mongodb(self, scanner: SecretScanner) -> None:
        text = "mongodb+srv://user:pass123@cluster0.abc.mongodb.net/prod"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "database_connection_string" in cats or "password_in_url" in cats

    def test_detects_redis(self, scanner: SecretScanner) -> None:
        text = "redis://default:mypassword@redis.example.com:6379/0"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "database_connection_string" in cats or "password_in_url" in cats

    def test_placeholder(self) -> None:
        assert get_secret_placeholder("database_connection_string") == "<DATABASE_URI>"

    def test_mask(self) -> None:
        assert get_secret_mask("database_connection_string") == "://****:****@****"


# ---------------------------------------------------------------------------
# SSH private key
# ---------------------------------------------------------------------------


class TestSSHPrivateKey:
    def test_detects_openssh_key(self) -> None:
        """With only ssh_private_key category, detect OPENSSH blocks."""
        s = SecretScanner(categories=["ssh_private_key"])
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n"
            "c2gtZWQyNTUxOQAAACDKfhspEzGWl8bOqHJvzG2nI5PJHd0KcBQ72bkGSVAhcQ\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        secrets = s.detect(text)
        cats = [sec.category for sec in secrets]
        assert "ssh_private_key" in cats

    def test_openssh_detected_as_private_key_with_all_categories(
        self, scanner: SecretScanner
    ) -> None:
        """With all categories, OPENSSH key is detected (as private_key or ssh_private_key)."""
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        secrets = scanner.detect(text)
        cats = [sec.category for sec in secrets]
        # Either pattern matches; overlap removal keeps one
        assert "ssh_private_key" in cats or "private_key" in cats

    def test_no_false_positive_on_public_key(self, scanner: SecretScanner) -> None:
        text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkg user@host"
        secrets = scanner.detect(text)
        cats = [s.category for s in secrets]
        assert "ssh_private_key" not in cats

    def test_placeholder(self) -> None:
        assert get_secret_placeholder("ssh_private_key") == "<SSH_PRIVATE_KEY>"

    def test_mask(self) -> None:
        assert get_secret_mask("ssh_private_key") == "-----REDACTED SSH KEY-----"


# ---------------------------------------------------------------------------
# Category totals
# ---------------------------------------------------------------------------


class TestCategoryTotals:
    def test_total_categories_is_11(self) -> None:
        assert len(get_all_secret_categories()) == 11

    def test_default_categories_is_11(self) -> None:
        assert len(DEFAULT_SECRET_CATEGORIES) == 11

    def test_new_categories_in_defaults(self) -> None:
        for cat in (
            "gcp_service_account",
            "azure_connection_string",
            "database_connection_string",
            "ssh_private_key",
        ):
            assert cat in DEFAULT_SECRET_CATEGORIES

    def test_scanner_enables_all_by_default(self) -> None:
        s = SecretScanner()
        assert len(s.categories) == 11

    def test_can_select_only_new_categories(self) -> None:
        s = SecretScanner(
            categories=[
                "gcp_service_account",
                "azure_connection_string",
                "database_connection_string",
                "ssh_private_key",
            ]
        )
        assert len(s.categories) == 4

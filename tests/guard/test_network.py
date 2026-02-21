"""Tests for network domain enforcement (enforcecore.guard.network)."""

from __future__ import annotations

import pytest

from enforcecore.core.types import DomainDeniedError
from enforcecore.guard.network import DomainChecker, _extract_strings

# ---------------------------------------------------------------------------
# Domain matching
# ---------------------------------------------------------------------------


class TestDomainChecker:
    def test_allowed_domain(self) -> None:
        checker = DomainChecker(
            allowed_domains=["api.openai.com"],
            deny_all_other=True,
        )
        assert checker.is_domain_allowed("api.openai.com")

    def test_denied_domain(self) -> None:
        checker = DomainChecker(
            allowed_domains=["api.openai.com"],
            deny_all_other=True,
        )
        assert not checker.is_domain_allowed("evil.com")

    def test_wildcard_allowed(self) -> None:
        checker = DomainChecker(
            allowed_domains=["*.internal.corp"],
            deny_all_other=True,
        )
        assert checker.is_domain_allowed("api.internal.corp")
        assert checker.is_domain_allowed("db.internal.corp")
        assert not checker.is_domain_allowed("evil.com")

    def test_denied_takes_priority(self) -> None:
        checker = DomainChecker(
            allowed_domains=["*.example.com"],
            denied_domains=["bad.example.com"],
            deny_all_other=True,
        )
        assert checker.is_domain_allowed("good.example.com")
        assert not checker.is_domain_allowed("bad.example.com")

    def test_wildcard_denied(self) -> None:
        checker = DomainChecker(
            denied_domains=["*.malware.xyz"],
            deny_all_other=False,
        )
        assert not checker.is_domain_allowed("c2.malware.xyz")
        assert checker.is_domain_allowed("safe.com")

    def test_case_insensitive(self) -> None:
        checker = DomainChecker(
            allowed_domains=["API.OpenAI.com"],
            deny_all_other=True,
        )
        assert checker.is_domain_allowed("api.openai.com")
        assert checker.is_domain_allowed("API.OPENAI.COM")

    def test_deny_all_other_false(self) -> None:
        checker = DomainChecker(
            allowed_domains=[],
            deny_all_other=False,
        )
        assert checker.is_domain_allowed("anything.com")

    def test_deny_all_other_true_empty_allowed(self) -> None:
        checker = DomainChecker(
            allowed_domains=[],
            deny_all_other=True,
        )
        assert not checker.is_domain_allowed("anything.com")

    def test_port_stripped(self) -> None:
        checker = DomainChecker(
            allowed_domains=["api.example.com"],
            deny_all_other=True,
        )
        assert checker.is_domain_allowed("api.example.com:8080")


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


class TestExtractDomains:
    def test_extract_http(self) -> None:
        checker = DomainChecker()
        domains = checker.extract_domains("visit https://api.openai.com/v1/chat")
        assert "api.openai.com" in domains

    def test_extract_multiple(self) -> None:
        checker = DomainChecker()
        text = "https://a.com and http://b.org"
        domains = checker.extract_domains(text)
        assert "a.com" in domains
        assert "b.org" in domains

    def test_no_urls(self) -> None:
        checker = DomainChecker()
        assert checker.extract_domains("no urls here") == []

    def test_extract_with_port(self) -> None:
        checker = DomainChecker()
        domains = checker.extract_domains("http://localhost:8080/api")
        assert "localhost" in domains


# ---------------------------------------------------------------------------
# Check text/args
# ---------------------------------------------------------------------------


class TestCheckText:
    def test_allowed_url_passes(self) -> None:
        checker = DomainChecker(
            allowed_domains=["api.openai.com"],
            deny_all_other=True,
        )
        checker.check_text("https://api.openai.com/v1/chat")  # Should not raise

    def test_denied_url_raises(self) -> None:
        checker = DomainChecker(
            allowed_domains=["api.openai.com"],
            deny_all_other=True,
        )
        with pytest.raises(DomainDeniedError, match=r"evil\.com"):
            checker.check_text("https://evil.com/steal")

    def test_no_urls_passes(self) -> None:
        checker = DomainChecker(
            allowed_domains=["api.openai.com"],
            deny_all_other=True,
        )
        checker.check_text("just some text")  # No URLs, should pass


class TestCheckArgs:
    def test_args_with_url(self) -> None:
        checker = DomainChecker(
            denied_domains=["*.malware.xyz"],
            deny_all_other=False,
        )
        with pytest.raises(DomainDeniedError):
            checker.check_args(
                ("fetch https://evil.malware.xyz/payload",),
                {},
            )

    def test_kwargs_with_url(self) -> None:
        checker = DomainChecker(
            denied_domains=["evil.com"],
            deny_all_other=False,
        )
        with pytest.raises(DomainDeniedError):
            checker.check_args(
                (),
                {"url": "https://evil.com/bad"},
            )

    def test_nested_args(self) -> None:
        checker = DomainChecker(
            denied_domains=["evil.com"],
            deny_all_other=False,
        )
        with pytest.raises(DomainDeniedError):
            checker.check_args(
                ({"urls": ["https://evil.com/page"]},),
                {},
            )

    def test_clean_args_pass(self) -> None:
        checker = DomainChecker(
            allowed_domains=["safe.com"],
            deny_all_other=True,
        )
        checker.check_args(
            ("https://safe.com/api",),
            {},
        )

    def test_non_string_args_pass(self) -> None:
        checker = DomainChecker(
            denied_domains=["evil.com"],
            deny_all_other=False,
        )
        checker.check_args((42, 3.14), {"n": 100})


# ---------------------------------------------------------------------------
# From policy
# ---------------------------------------------------------------------------


class TestFromPolicy:
    def test_disabled(self) -> None:
        from enforcecore.core.policy import NetworkPolicy

        policy = NetworkPolicy(enabled=False)
        assert DomainChecker.from_policy(policy) is None

    def test_enabled(self) -> None:
        from enforcecore.core.policy import NetworkPolicy

        policy = NetworkPolicy(
            enabled=True,
            allowed_domains=["api.example.com"],
        )
        checker = DomainChecker.from_policy(policy)
        assert checker is not None
        assert checker.is_domain_allowed("api.example.com")


# ---------------------------------------------------------------------------
# Repr & helpers
# ---------------------------------------------------------------------------


class TestRepr:
    def test_repr(self) -> None:
        checker = DomainChecker(
            allowed_domains=["a.com", "b.com"],
            denied_domains=["c.com"],
        )
        r = repr(checker)
        assert "DomainChecker" in r
        assert "2" in r
        assert "1" in r


class TestExtractStrings:
    def test_flat(self) -> None:
        assert _extract_strings(("a", "b")) == ["a", "b"]

    def test_nested(self) -> None:
        result = _extract_strings(({"k": "v"},))
        assert result == ["v"]

    def test_non_strings(self) -> None:
        assert _extract_strings((42,)) == []

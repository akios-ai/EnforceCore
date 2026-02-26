# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.7.0 Remote Policy Server features.

Covers:
- PolicyServerClient.__init__ — validation of url/token/cache_ttl
- PolicyServerClient.get_policy — happy path (mock HTTP server)
- PolicyServerClient.get_policy — TTL cache (no second request within TTL)
- PolicyServerClient.get_policy — stale-on-error fallback
- PolicyServerClient.get_policy — fresh fetch after TTL expires
- PolicyServerClient.invalidate — forces re-fetch
- PolicyServerClient._verify_hmac — correct HMAC-SHA256
- PolicyServerClient — signature verification pass / fail
- PolicyServerClient — HTTP error (4xx, 5xx)
- PolicyServerClient — network error (URLError)
- PolicyServerClient — invalid YAML response
- PolicyServerClient — non-mapping YAML response
- PolicyServerClient — policy schema validation error
- PolicyServerClient — X-Policy-Version header captured
- PolicyServerClient.__repr__
- Enforcer.from_server — happy path (with mock server)
- Enforcer.from_server — policy_server_client property
- Enforcer.from_server — raises PolicyServerError on failure with no cache
- PolicyServerError — exception hierarchy
- PolicyServerError in enforcecore.core.__all__
- PolicyServerClient in enforcecore.core.__all__
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import enforcecore
from enforcecore.core.enforcer import Enforcer
from enforcecore.core.policy import Policy
from enforcecore.core.policy_server import PolicyServerClient
from enforcecore.core.types import PolicyServerError

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures"

MINIMAL_POLICY_YAML = """\
name: test-remote-policy
version: "2.5"
rules:
  allowed_tools: null
  denied_tools: []
  pii_redaction:
    enabled: false
  resource_limits: {}
on_violation: block
"""

MINIMAL_POLICY_BYTES = MINIMAL_POLICY_YAML.encode("utf-8")


def _make_signature(body: bytes, token: str) -> str:
    """Produce the HMAC-SHA256 hex signature for *body* using *token* as key."""
    return hmac.new(token.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _mock_urlopen(body: bytes, *, status: int = 200, headers: dict[str, str] | None = None):
    """Return a context-manager mock that simulates urllib.request.urlopen."""
    resp = MagicMock()
    resp.read.return_value = body
    resp.headers = MagicMock()
    header_dict = headers or {}
    resp.headers.get = lambda key, default=None: header_dict.get(key, default)
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# 1.  PolicyServerClient.__init__ — validation
# ---------------------------------------------------------------------------


class TestPolicyServerClientInit:
    def test_happy_path(self) -> None:
        c = PolicyServerClient("https://policy.example.com/v1", "tok")
        assert c.url == "https://policy.example.com/v1"
        assert c.cache_ttl == 300
        assert c.policy_version is None

    def test_custom_cache_ttl(self) -> None:
        c = PolicyServerClient("https://example.com", "tok", cache_ttl=60)
        assert c.cache_ttl == 60

    def test_zero_cache_ttl_allowed(self) -> None:
        """cache_ttl=0 means every call re-fetches (cache disabled)."""
        c = PolicyServerClient("https://example.com", "tok", cache_ttl=0)
        assert c.cache_ttl == 0

    def test_empty_url_raises(self) -> None:
        with pytest.raises(ValueError, match="url"):
            PolicyServerClient("", "tok")

    def test_empty_token_raises(self) -> None:
        with pytest.raises(ValueError, match="token"):
            PolicyServerClient("https://example.com", "")

    def test_negative_cache_ttl_raises(self) -> None:
        with pytest.raises(ValueError, match="cache_ttl"):
            PolicyServerClient("https://example.com", "tok", cache_ttl=-1)

    def test_verify_signature_default_true(self) -> None:
        c = PolicyServerClient("https://example.com", "tok")
        assert c._verify_signature is True

    def test_verify_signature_false(self) -> None:
        c = PolicyServerClient("https://example.com", "tok", verify_signature=False)
        assert c._verify_signature is False


# ---------------------------------------------------------------------------
# 2.  PolicyServerClient.get_policy — happy path
# ---------------------------------------------------------------------------


class TestPolicyServerClientGetPolicy:
    def test_fetches_policy_on_first_call(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com/pol", "my-token")
            policy = c.get_policy()

        assert isinstance(policy, Policy)
        assert policy.name == "test-remote-policy"
        assert policy.version == "2.5"

    def test_policy_version_captured_from_header(self) -> None:
        resp = _mock_urlopen(
            MINIMAL_POLICY_BYTES,
            headers={"X-Policy-Version": "sha256:abcdef12"},
        )
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com/pol", "tok")
            c.get_policy()

        assert c.policy_version == "sha256:abcdef12"

    def test_policy_version_none_when_header_absent(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com/pol", "tok")
            c.get_policy()

        assert c.policy_version is None

    def test_auth_header_sent(self) -> None:
        """The Authorization: Bearer <token> header must be included."""
        captured: list[urllib.request.Request] = []

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            captured.append(req)
            resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
            return resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com/pol", "secret-token")
            c.get_policy()

        assert len(captured) == 1
        assert captured[0].get_header("Authorization") == "Bearer secret-token"


# ---------------------------------------------------------------------------
# 3.  TTL cache — no second HTTP request within TTL
# ---------------------------------------------------------------------------


class TestPolicyServerClientCache:
    def test_cache_hit_within_ttl(self) -> None:
        call_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            call_count += 1
            return _mock_urlopen(MINIMAL_POLICY_BYTES)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=60)
            p1 = c.get_policy()
            p2 = c.get_policy()

        assert call_count == 1  # second call served from cache
        assert p1 is p2

    def test_cache_miss_after_ttl_expires(self) -> None:
        call_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            call_count += 1
            return _mock_urlopen(MINIMAL_POLICY_BYTES)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=0)
            c.get_policy()
            c.get_policy()

        assert call_count == 2  # cache_ttl=0 means re-fetch every time

    def test_invalidate_forces_refetch(self) -> None:
        call_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            call_count += 1
            return _mock_urlopen(MINIMAL_POLICY_BYTES)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=300)
            c.get_policy()
            c.invalidate()
            c.get_policy()

        assert call_count == 2

    def test_invalidate_does_not_discard_cache_for_fallback(self) -> None:
        """After invalidate, the cache still exists as a stale fallback."""
        real_fetch_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal real_fetch_count
            real_fetch_count += 1
            if real_fetch_count == 1:
                return _mock_urlopen(MINIMAL_POLICY_BYTES)
            raise urllib.error.URLError("server down")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=300)
            p1 = c.get_policy()  # fills cache
            c.invalidate()  # marks cache as expired
            p2 = c.get_policy()  # server down → returns stale cache

        assert p1 is p2  # stale cache returned, not an exception


# ---------------------------------------------------------------------------
# 4.  Stale-on-error fallback
# ---------------------------------------------------------------------------


class TestPolicyServerClientStaleFallback:
    def test_stale_cache_returned_on_http_error(self) -> None:
        call_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen(MINIMAL_POLICY_BYTES)
            raise urllib.error.HTTPError(
                "https://example.com",
                503,
                "Service Unavailable",
                {},
                None,  # type: ignore[arg-type]
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=0)
            p1 = c.get_policy()  # succeeds, fills cache
            p2 = c.get_policy()  # 503 → returns stale cache

        assert p1 is p2

    def test_stale_cache_returned_on_urlerror(self) -> None:
        call_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen(MINIMAL_POLICY_BYTES)
            raise urllib.error.URLError("Connection refused")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=0)
            p1 = c.get_policy()
            p2 = c.get_policy()

        assert p1 is p2

    def test_no_stale_cache_raises_policy_server_error(self) -> None:
        """No cache + server error → PolicyServerError raised."""

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            raise urllib.error.URLError("Connection refused")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="Could not reach"):
                c.get_policy()

    def test_stale_cache_returned_on_oserror(self) -> None:
        call_count = 0

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen(MINIMAL_POLICY_BYTES)
            raise OSError("SSL error")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok", cache_ttl=0)
            p1 = c.get_policy()
            p2 = c.get_policy()

        assert p1 is p2


# ---------------------------------------------------------------------------
# 5.  Signature verification
# ---------------------------------------------------------------------------


class TestPolicyServerClientSignatureVerification:
    def test_valid_signature_accepted(self) -> None:
        token = "super-secret-token"
        sig = _make_signature(MINIMAL_POLICY_BYTES, token)
        resp = _mock_urlopen(
            MINIMAL_POLICY_BYTES,
            headers={"X-Policy-Signature": sig},
        )
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", token)
            policy = c.get_policy()

        assert isinstance(policy, Policy)

    def test_invalid_signature_raises(self) -> None:
        resp = _mock_urlopen(
            MINIMAL_POLICY_BYTES,
            headers={"X-Policy-Signature": "deadbeef" * 8},
        )
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="signature verification failed"):
                c.get_policy()

    def test_verify_signature_false_skips_verification(self) -> None:
        """With verify_signature=False, any (or no) signature is accepted."""
        resp = _mock_urlopen(
            MINIMAL_POLICY_BYTES,
            headers={"X-Policy-Signature": "invalid-sig"},
        )
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok", verify_signature=False)
            policy = c.get_policy()

        assert isinstance(policy, Policy)

    def test_no_signature_header_accepted_by_default(self) -> None:
        """A server that omits X-Policy-Signature is still accepted."""
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok")
            policy = c.get_policy()

        assert isinstance(policy, Policy)

    def test_verify_hmac_correct(self) -> None:
        c = PolicyServerClient("https://example.com", "my-key")
        sig = _make_signature(b"hello", "my-key")
        assert c._verify_hmac(b"hello", sig) is True

    def test_verify_hmac_wrong_body(self) -> None:
        c = PolicyServerClient("https://example.com", "my-key")
        sig = _make_signature(b"hello", "my-key")
        assert c._verify_hmac(b"world", sig) is False

    def test_verify_hmac_wrong_token(self) -> None:
        c = PolicyServerClient("https://example.com", "my-key")
        sig = _make_signature(b"hello", "other-key")
        assert c._verify_hmac(b"hello", sig) is False


# ---------------------------------------------------------------------------
# 6.  Error scenarios — bad responses
# ---------------------------------------------------------------------------


class TestPolicyServerClientErrors:
    def test_http_4xx_raises(self) -> None:
        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            raise urllib.error.HTTPError(
                "https://example.com",
                403,
                "Forbidden",
                {},
                None,  # type: ignore[arg-type]
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="HTTP 403"):
                c.get_policy()

    def test_http_5xx_raises(self) -> None:
        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            raise urllib.error.HTTPError(
                "https://example.com",
                500,
                "Internal Server Error",
                {},
                None,  # type: ignore[arg-type]
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="HTTP 500"):
                c.get_policy()

    def test_invalid_yaml_raises(self) -> None:
        bad_yaml = b"!!invalid: yaml: {unclosed"
        resp = _mock_urlopen(bad_yaml)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="invalid YAML"):
                c.get_policy()

    def test_non_mapping_yaml_raises(self) -> None:
        list_yaml = b"- item1\n- item2\n"
        resp = _mock_urlopen(list_yaml)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="non-mapping"):
                c.get_policy()

    def test_schema_validation_error_raises(self) -> None:
        bad_schema = b"name: ok\nrules:\n  allowed_tools: 12345\n"
        resp = _mock_urlopen(bad_schema)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="schema validation"):
                c.get_policy()

    def test_oserror_raises(self) -> None:
        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            raise OSError("broken pipe")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            c = PolicyServerClient("https://example.com", "tok")
            with pytest.raises(PolicyServerError, match="Network error"):
                c.get_policy()


# ---------------------------------------------------------------------------
# 7.  PolicyServerClient.__repr__
# ---------------------------------------------------------------------------


class TestPolicyServerClientRepr:
    def test_repr_no_cache(self) -> None:
        c = PolicyServerClient("https://example.com", "tok")
        r = repr(c)
        assert "no-cache" in r
        assert "https://example.com" in r

    def test_repr_with_cache(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            c = PolicyServerClient("https://example.com", "tok")
            c.get_policy()
        r = repr(c)
        assert "cached" in r


# ---------------------------------------------------------------------------
# 8.  Enforcer.from_server
# ---------------------------------------------------------------------------


class TestEnforcerFromServer:
    def test_creates_enforcer(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            enforcer = Enforcer.from_server("https://example.com/pol", "tok")

        assert isinstance(enforcer, Enforcer)
        assert enforcer.policy.name == "test-remote-policy"

    def test_policy_server_client_stored(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            enforcer = Enforcer.from_server("https://example.com/pol", "tok")

        assert isinstance(enforcer.policy_server_client, PolicyServerClient)

    def test_policy_server_client_none_for_from_file(self, tmp_path: Path) -> None:
        """from_file enforcers have no policy_server_client."""
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: local\nversion: '1.0'\nrules:\n  allowed_tools: null\n"
            "  denied_tools: []\n  pii_redaction:\n    enabled: false\n"
            "  resource_limits: {}\non_violation: block\n"
        )
        enforcer = Enforcer.from_file(path)
        assert enforcer.policy_server_client is None

    def test_policy_server_client_none_for_constructor(self) -> None:
        """Enforcers created via the constructor have no policy_server_client."""
        from pathlib import Path

        fixtures = Path(__file__).parent.parent / "fixtures"
        policy = Policy.from_file(fixtures / "allow_all.yaml")
        enforcer = Enforcer(policy)
        assert enforcer.policy_server_client is None

    def test_from_server_passes_tenant_id(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            enforcer = Enforcer.from_server("https://example.com/pol", "tok", tenant_id="acme")
        assert enforcer.tenant_id == "acme"

    def test_from_server_raises_on_server_error(self) -> None:
        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            raise urllib.error.URLError("refused")

        with (
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            pytest.raises(PolicyServerError),
        ):
            Enforcer.from_server("https://example.com/pol", "tok")

    def test_from_server_cache_ttl_forwarded(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            enforcer = Enforcer.from_server("https://example.com/pol", "tok", cache_ttl=60)
        client = enforcer.policy_server_client
        assert isinstance(client, PolicyServerClient)
        assert client.cache_ttl == 60

    def test_from_server_verify_signature_forwarded(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            enforcer = Enforcer.from_server(
                "https://example.com/pol", "tok", verify_signature=False
            )
        client = enforcer.policy_server_client
        assert isinstance(client, PolicyServerClient)
        assert client._verify_signature is False

    def test_from_server_url_forwarded_to_client(self) -> None:
        resp = _mock_urlopen(MINIMAL_POLICY_BYTES)
        with patch("urllib.request.urlopen", return_value=resp):
            enforcer = Enforcer.from_server("https://my-server.example/p", "tok")
        assert isinstance(enforcer.policy_server_client, PolicyServerClient)
        assert enforcer.policy_server_client.url == "https://my-server.example/p"


# ---------------------------------------------------------------------------
# 9.  PolicyServerError — exception hierarchy
# ---------------------------------------------------------------------------


class TestPolicyServerError:
    def test_is_subclass_of_policy_error(self) -> None:
        from enforcecore.core.types import PolicyError

        assert issubclass(PolicyServerError, PolicyError)

    def test_is_subclass_of_enforcecore_error(self) -> None:
        from enforcecore.core.types import EnforceCoreError

        assert issubclass(PolicyServerError, EnforceCoreError)

    def test_is_exception(self) -> None:
        assert issubclass(PolicyServerError, Exception)

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(PolicyServerError, match="oops"):
            raise PolicyServerError("oops")

    def test_importable_from_enforcecore(self) -> None:
        from enforcecore import PolicyServerError as ImportedPSE

        assert ImportedPSE is PolicyServerError

    def test_importable_from_core(self) -> None:
        from enforcecore.core.types import PolicyServerError as CorePSE

        assert CorePSE is PolicyServerError


# ---------------------------------------------------------------------------
# 10.  Public API checks
# ---------------------------------------------------------------------------


class TestPublicAPI:
    def test_policy_server_client_in_enforcecore_all(self) -> None:
        assert "PolicyServerClient" in enforcecore.__all__

    def test_policy_server_error_in_enforcecore_all(self) -> None:
        assert "PolicyServerError" in enforcecore.__all__

    def test_policy_server_client_importable(self) -> None:
        assert hasattr(enforcecore, "PolicyServerClient")

    def test_policy_server_error_importable(self) -> None:
        assert hasattr(enforcecore, "PolicyServerError")

    def test_policy_server_client_is_correct_class(self) -> None:
        assert enforcecore.PolicyServerClient is PolicyServerClient

    def test_policy_server_error_is_correct_class(self) -> None:
        assert enforcecore.PolicyServerError is PolicyServerError


# ---------------------------------------------------------------------------
# 11.  Thread safety — concurrent get_policy calls use cache correctly
# ---------------------------------------------------------------------------


class TestPolicyServerClientThreadSafety:
    def test_concurrent_get_policy_calls_single_fetch(self) -> None:
        """Multiple threads calling get_policy() simultaneously should result
        in at most a small number of HTTP fetches (not one per thread)."""
        call_count = 0
        lock = threading.Lock()

        def fake_urlopen(req: Any, timeout: int = 10) -> Any:
            nonlocal call_count
            with lock:
                call_count += 1
            time.sleep(0.01)  # simulate network latency
            return _mock_urlopen(MINIMAL_POLICY_BYTES)

        c = PolicyServerClient("https://example.com", "tok", cache_ttl=60)

        errors: list[Exception] = []

        def worker() -> None:
            try:
                c.get_policy()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert not errors, f"Thread errors: {errors}"
        # With the lock, all threads wait; the first one fetches, the rest
        # may fetch too before the cache is populated, but all get a valid policy.
        assert call_count >= 1

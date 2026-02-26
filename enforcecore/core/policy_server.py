# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Remote Policy Server client for EnforceCore.

Implements pull-only policy fetching from a remote policy server with
HMAC-SHA256 signature verification, TTL caching, and stale-on-error
graceful degradation.

Typical usage::

    import os
    from enforcecore import PolicyServerClient

    client = PolicyServerClient(
        "https://policy.acme.com/agents/chatbot-v2",
        token=os.environ["POLICY_SERVER_TOKEN"],
        cache_ttl=300,
    )
    policy = client.get_policy()

Or via the :class:`~enforcecore.core.enforcer.Enforcer` factory::

    enforcer = Enforcer.from_server(
        "https://policy.acme.com/agents/chatbot-v2",
        token=os.environ["POLICY_SERVER_TOKEN"],
        cache_ttl=300,
    )

.. versionadded:: 1.7.0
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

import yaml

from enforcecore.core.types import PolicyServerError, PolicyValidationError

if TYPE_CHECKING:
    from enforcecore.core.policy import Policy


class PolicyServerClient:
    """Client for fetching and caching policies from a remote policy server.

    The client implements pull-only architecture: the enforcer explicitly
    calls :meth:`get_policy` at startup or on cache miss.  The server never
    pushes policy updates.

    **Signature verification** — if the server includes an
    ``X-Policy-Signature`` HTTP response header (HMAC-SHA256 of the response
    body using the bearer token as the key), the client verifies the signature
    before loading the policy.  Requests to servers that do not send the
    header are still accepted when ``verify_signature=False``.

    **Graceful degradation** — if the server is unreachable *and* a previously
    fetched policy is in the cache (even if expired), the cached policy is
    returned rather than raising an exception.  This prevents live-traffic
    disruption during transient server outages.

    **Thread safety** — all cache access is protected by an internal
    :class:`threading.Lock`.

    Example::

        client = PolicyServerClient(
            "https://policy.acme.com/agents/chatbot-v2",
            token=os.environ["POLICY_SERVER_TOKEN"],
            cache_ttl=300,
        )
        policy = client.get_policy()

    .. versionadded:: 1.7.0
    """

    __slots__ = (
        "_cache_ttl",
        "_cached_at",
        "_cached_policy",
        "_lock",
        "_policy_version",
        "_token",
        "_url",
        "_verify_signature",
    )

    def __init__(
        self,
        url: str,
        token: str,
        *,
        cache_ttl: int = 300,
        verify_signature: bool = True,
    ) -> None:
        """Initialise the policy server client.

        Args:
            url: Full URL of the policy endpoint.  The client sends a
                ``GET`` request to this URL on every cache miss.
            token: Bearer token used for authentication and (optionally)
                HMAC-SHA256 signature verification.
            cache_ttl: Seconds before the cached policy expires and the
                client re-fetches from the server.  Defaults to ``300``
                (5 minutes).  Pass ``0`` to disable caching.
            verify_signature: When ``True`` (default), any
                ``X-Policy-Signature`` response header is verified via
                HMAC-SHA256.  When ``False``, the header is ignored even if
                present.

        Raises:
            ValueError: If *url* or *token* is empty, or *cache_ttl* is
                negative.
        """
        if not url:
            raise ValueError("url must not be empty")
        if not token:
            raise ValueError("token must not be empty")
        if cache_ttl < 0:
            raise ValueError("cache_ttl must be >= 0")

        self._url = url
        self._token = token
        self._cache_ttl = cache_ttl
        self._verify_signature = verify_signature
        self._lock = threading.Lock()
        self._cached_policy: Policy | None = None
        self._cached_at: float = 0.0
        self._policy_version: str | None = None

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        """The policy server URL passed at construction."""
        return self._url

    @property
    def cache_ttl(self) -> int:
        """Cache time-to-live in seconds."""
        return self._cache_ttl

    @property
    def policy_version(self) -> str | None:
        """Version string returned by the server on the last successful fetch.

        The server communicates the policy version via the
        ``X-Policy-Version`` HTTP response header.  Returns ``None`` if no
        successful fetch has occurred yet, or if the server does not send the
        header.
        """
        return self._policy_version

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def get_policy(self) -> Policy:
        """Return the current policy, fetching from the server when needed.

        The cache is considered *fresh* if the last successful fetch
        occurred less than :attr:`cache_ttl` seconds ago.  A fresh cache
        is returned immediately without a network round-trip.

        On cache miss the client fetches from the server, verifies the
        response (if a signature header is present and
        ``verify_signature=True``), and updates the cache.

        On fetch failure the client returns the stale cache if one exists.
        If no cache is available at all, :exc:`PolicyServerError` is raised.

        Returns:
            The current :class:`~enforcecore.core.policy.Policy`.

        Raises:
            PolicyServerError: If the server is unreachable and no cached
                policy is available.
        """
        with self._lock:
            if self._is_cache_fresh():
                assert self._cached_policy is not None  # guarded by _is_cache_fresh
                return self._cached_policy

            try:
                body, signature, version = self._fetch_from_server()
            except PolicyServerError:
                if self._cached_policy is not None:
                    # Stale-on-error: serve cached policy during outage.
                    return self._cached_policy
                raise

            if signature and self._verify_signature and not self._verify_hmac(body, signature):
                raise PolicyServerError(
                    f"Policy signature verification failed for {self._url!r}. "
                    "The response body does not match the X-Policy-Signature header. "
                    "Ensure the server signs with the same token."
                )

            policy = self._parse_policy(body)
            self._cached_policy = policy
            self._cached_at = time.monotonic()
            if version:
                self._policy_version = version
            return policy

    def invalidate(self) -> None:
        """Force the next :meth:`get_policy` call to re-fetch from the server.

        Thread-safe.  The existing cached policy is **not** discarded — it
        remains available as a stale fallback if the server is unreachable
        after invalidation.
        """
        with self._lock:
            self._cached_at = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_cache_fresh(self) -> bool:
        """Return ``True`` if the cache exists and has not expired."""
        if self._cached_policy is None:
            return False
        age = time.monotonic() - self._cached_at
        return age < self._cache_ttl

    def _fetch_from_server(self) -> tuple[bytes, str | None, str | None]:
        """Perform the HTTP GET and return ``(body, signature, version)``.

        Raises:
            PolicyServerError: on HTTP errors or connection failures.
        """
        req = urllib.request.Request(
            self._url,
            headers={"Authorization": f"Bearer {self._token}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body: bytes = resp.read()
                signature: str | None = resp.headers.get("X-Policy-Signature")
                version: str | None = resp.headers.get("X-Policy-Version")
                return body, signature, version
        except urllib.error.HTTPError as exc:
            raise PolicyServerError(
                f"Policy server returned HTTP {exc.code} for {self._url!r}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise PolicyServerError(
                f"Could not reach policy server at {self._url!r}: {exc.reason}"
            ) from exc
        except OSError as exc:
            raise PolicyServerError(
                f"Network error fetching policy from {self._url!r}: {exc}"
            ) from exc

    def _verify_hmac(self, body: bytes, signature: str) -> bool:
        """Return ``True`` if *signature* is valid HMAC-SHA256 of *body*.

        The HMAC key is the bearer token, encoded as UTF-8.  Uses
        :func:`hmac.compare_digest` for a timing-safe comparison.
        """
        expected = hmac.new(
            self._token.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _parse_policy(self, body: bytes) -> Policy:
        """Parse *body* as YAML and return a :class:`~enforcecore.core.policy.Policy`.

        Raises:
            PolicyServerError: if the body is not valid YAML or does not
                conform to the policy schema.
        """
        from enforcecore.core.policy import Policy

        try:
            data: Any = yaml.safe_load(body)
        except yaml.YAMLError as exc:
            raise PolicyServerError(
                f"Policy server returned invalid YAML from {self._url!r}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise PolicyServerError(
                f"Policy server returned non-mapping YAML from {self._url!r} "
                f"(got {type(data).__name__!r})"
            )

        try:
            return Policy.from_dict(data, source=self._url)
        except PolicyValidationError as exc:
            raise PolicyServerError(
                f"Policy from {self._url!r} failed schema validation: {exc}"
            ) from exc

    def __repr__(self) -> str:
        cached = "cached" if self._cached_policy is not None else "no-cache"
        return (
            f"PolicyServerClient(url={self._url!r}, "
            f"cache_ttl={self._cache_ttl}, "
            f"verify_signature={self._verify_signature}, "
            f"{cached})"
        )

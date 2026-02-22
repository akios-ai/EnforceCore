# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.integrations._base — shared adapter utilities."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore.core.types import ToolDeniedError
from enforcecore.integrations._base import require_package, wrap_with_policy

if TYPE_CHECKING:
    from enforcecore.core.policy import Policy

# ---------------------------------------------------------------------------
# require_package
# ---------------------------------------------------------------------------


class TestRequirePackage:
    """Tests for the require_package helper."""

    def test_installed_package_succeeds(self) -> None:
        """stdlib 'os' is always importable — should not raise."""
        require_package("os")

    def test_missing_package_raises(self) -> None:
        """A non-existent package should raise ImportError."""
        with pytest.raises(ImportError, match="pip install"):
            require_package("totally_fake_nonexistent_pkg_12345")

    def test_error_message_default_pip_name(self) -> None:
        """Error message should show the package name as the pip install target."""
        with pytest.raises(ImportError, match="pip install totally_fake_pkg"):
            require_package("totally_fake_pkg")

    def test_error_message_custom_pip_name(self) -> None:
        """When pip_name is given, it should appear in the install command."""
        with pytest.raises(ImportError, match="pip install my-custom-package"):
            require_package("nonexistent_xyz", pip_name="my-custom-package")

    def test_error_mentions_package_name(self) -> None:
        """Error should mention the package name in the explanation text."""
        with pytest.raises(ImportError, match="'nonexistent_xyz'"):
            require_package("nonexistent_xyz")


# ---------------------------------------------------------------------------
# wrap_with_policy — sync
# ---------------------------------------------------------------------------


class TestWrapWithPolicySync:
    """Wrap synchronous functions with policy enforcement."""

    def test_allowed_call_returns_result(self, allow_all_policy: Policy) -> None:
        """Allowed tools should execute normally and return the result."""

        def add(a: int, b: int) -> int:
            return a + b

        wrapped = wrap_with_policy(add, policy=allow_all_policy)
        assert wrapped(2, 3) == 5

    def test_denied_call_raises(self, deny_all_policy: Policy) -> None:
        """Denied tools should raise ToolDeniedError."""

        def dangerous(cmd: str) -> str:
            return cmd

        wrapped = wrap_with_policy(dangerous, policy=deny_all_policy)
        with pytest.raises(ToolDeniedError):
            wrapped("rm -rf /")

    def test_preserves_name(self, allow_all_policy: Policy) -> None:
        """functools.wraps should preserve the original __name__."""

        def my_function(x: int) -> int:
            return x

        wrapped = wrap_with_policy(my_function, policy=allow_all_policy)
        assert wrapped.__name__ == "my_function"

    def test_preserves_docstring(self, allow_all_policy: Policy) -> None:
        """functools.wraps should preserve the original __doc__."""

        def my_function(x: int) -> int:
            """My docstring."""
            return x

        wrapped = wrap_with_policy(my_function, policy=allow_all_policy)
        assert wrapped.__doc__ == "My docstring."

    def test_custom_tool_name(self, allow_all_policy: Policy) -> None:
        """Custom tool_name is used for enforcement, not __name__."""

        def add(a: int, b: int) -> int:
            return a + b

        wrapped = wrap_with_policy(add, policy=allow_all_policy, tool_name="calculator")
        assert wrapped(2, 3) == 5

    def test_specific_tool_allowed(self, specific_tools_policy: Policy) -> None:
        """A tool in the allowed list should pass."""

        def search_web(query: str) -> str:
            return f"results for {query}"

        wrapped = wrap_with_policy(search_web, policy=specific_tools_policy)
        assert wrapped("python") == "results for python"

    def test_specific_tool_blocked(self, specific_tools_policy: Policy) -> None:
        """A tool NOT in the allowed list should be blocked."""

        def execute_shell(cmd: str) -> str:
            return cmd

        wrapped = wrap_with_policy(execute_shell, policy=specific_tools_policy)
        with pytest.raises(ToolDeniedError):
            wrapped("whoami")


# ---------------------------------------------------------------------------
# wrap_with_policy — async
# ---------------------------------------------------------------------------


class TestWrapWithPolicyAsync:
    """Wrap asynchronous functions with policy enforcement."""

    async def test_allowed_async_call(self, allow_all_policy: Policy) -> None:
        """Allowed async tools should execute and return the result."""

        async def fetch(url: str) -> str:
            return f"data from {url}"

        wrapped = wrap_with_policy(fetch, policy=allow_all_policy)
        result = await wrapped("https://example.com")
        assert result == "data from https://example.com"

    async def test_denied_async_call(self, deny_all_policy: Policy) -> None:
        """Denied async tools should raise ToolDeniedError."""

        async def delete_everything() -> str:
            return "deleted"

        wrapped = wrap_with_policy(delete_everything, policy=deny_all_policy)
        with pytest.raises(ToolDeniedError):
            await wrapped()

    async def test_async_preserves_name(self, allow_all_policy: Policy) -> None:
        """Async wrapper preserves __name__."""

        async def my_async_fn(x: int) -> int:
            return x

        wrapped = wrap_with_policy(my_async_fn, policy=allow_all_policy)
        assert wrapped.__name__ == "my_async_fn"


# ---------------------------------------------------------------------------
# wrap_with_policy — edge cases
# ---------------------------------------------------------------------------


class TestWrapEdgeCases:
    """Edge-case behaviour for wrap_with_policy."""

    def test_no_policy_no_default_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a policy and no ENFORCECORE_DEFAULT_POLICY, raise."""
        from enforcecore.core.config import settings
        from enforcecore.core.types import PolicyLoadError

        monkeypatch.setattr(settings, "default_policy", None)

        def add(a: int, b: int) -> int:
            return a + b

        with pytest.raises(PolicyLoadError, match="No policy provided"):
            wrap_with_policy(add)

    def test_policy_from_path(self, fixtures_dir: object) -> None:
        """A string path should resolve to a Policy via from_file."""
        from pathlib import Path

        path = Path(str(fixtures_dir)) / "allow_all.yaml"

        def add(a: int, b: int) -> int:
            return a + b

        wrapped = wrap_with_policy(add, policy=str(path))
        assert wrapped(1, 2) == 3

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Subprocess sandbox — post-execution isolation for enforced tool calls.

Provides process-level isolation for tool calls that have been approved by
the policy engine.  Closes the gap between *pre-decision enforcement*
(what EnforceCore has always done) and *post-execution enforcement* (what
the sandbox adds).

Without sandbox::

    policy decides → tool runs in-process → output checked

With sandbox::

    policy decides → tool runs in isolated subprocess → output checked
                      ↑ memory limit, CPU limit,
                        restricted env, custom cwd

Usage (manual)::

    from enforcecore.sandbox import SubprocessSandbox, SandboxConfig

    config = SandboxConfig(max_memory_mb=256, max_cpu_seconds=10.0)
    sandbox = SubprocessSandbox(config)
    result = sandbox.run(my_function, "arg1", key="value")

Usage (via policy)::

    # policy.yaml
    sandbox:
      enabled: true
      strategy: subprocess
      max_memory_mb: 256
      max_cpu_seconds: 30

    @enforce(policy="policy.yaml")
    def run_code(code: str) -> str:
        exec(code)
        return "done"

"""

from enforcecore.sandbox.config import SandboxConfig, SandboxStrategy
from enforcecore.sandbox.errors import (
    SandboxMemoryError,
    SandboxTimeoutError,
    SandboxViolationError,
)
from enforcecore.sandbox.runner import SubprocessSandbox

__all__ = [
    "SandboxConfig",
    "SandboxMemoryError",
    "SandboxStrategy",
    "SandboxTimeoutError",
    "SandboxViolationError",
    "SubprocessSandbox",
]

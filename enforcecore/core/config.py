"""Global configuration for EnforceCore via pydantic-settings.

Settings can be provided via:
1. Constructor arguments (highest priority)
2. Environment variables prefixed with ``ENFORCECORE_``
3. Defaults (lowest priority)

Example::

    # Via environment
    export ENFORCECORE_DEFAULT_POLICY=policies/strict.yaml
    export ENFORCECORE_LOG_LEVEL=DEBUG

    # Via code
    from enforcecore.core.config import Settings
    settings = Settings(default_policy="policies/strict.yaml")
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Global EnforceCore settings.

    Attributes:
        default_policy: Path to the default policy YAML file.
            Used when ``@enforce()`` is called without an explicit policy.
        audit_enabled: Whether to record audit entries. Defaults to ``True``.
        audit_path: Directory where audit JSONL files are written.
        redaction_enabled: Whether PII redaction is active. Defaults to ``True``.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        fail_open: If ``True``, enforcement errors let the call through
            instead of blocking. **NEVER set to True in production.**
            Defaults to ``False``.
        cost_budget_usd: Global cost budget across all enforced calls.
            ``None`` means no limit.
    """

    model_config = {"env_prefix": "ENFORCECORE_"}

    default_policy: Path | None = None
    audit_enabled: bool = True
    audit_path: Path = Path("./audit_logs")
    redaction_enabled: bool = True
    log_level: str = "INFO"
    fail_open: bool = False
    cost_budget_usd: float | None = None


# Module-level singleton — importable from anywhere.
# Can be replaced at startup via ``enforcecore.core.config.settings = Settings(...)``.
settings = Settings()

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Merkle-tree based audit trail."""

from enforcecore.auditor.engine import (
    AuditEntry,
    Auditor,
    VerificationResult,
    load_trail,
    verify_trail,
)
from enforcecore.auditor.immutable import (
    AppendOnlyError,
    is_append_only,
    platform_support_info,
    protect_append_only,
)
from enforcecore.auditor.witness import (
    CallbackWitness,
    FileWitness,
    LogWitness,
    WitnessBackend,
    WitnessRecord,
    WitnessVerificationResult,
    verify_with_witness,
)

__all__ = [
    "AppendOnlyError",
    "AuditEntry",
    "Auditor",
    "CallbackWitness",
    "FileWitness",
    "LogWitness",
    "VerificationResult",
    "WitnessBackend",
    "WitnessRecord",
    "WitnessVerificationResult",
    "is_append_only",
    "load_trail",
    "platform_support_info",
    "protect_append_only",
    "verify_trail",
    "verify_with_witness",
]

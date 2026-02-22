# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for EnforceCore.

These tests exercise the full enforcement pipeline end-to-end with no mocks.
They override the global ``_disable_audit_globally`` fixture to enable real
audit trail writing and verification.
"""

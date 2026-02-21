"""API compatibility tests for EnforceCore.

This module verifies that every symbol in ``enforcecore.__all__`` is
importable, has the expected type (class, function, enum, etc.), and
has not had its signature accidentally changed.

These tests act as a **contract** — if any test here fails, it means the
public API surface has changed and the change must be intentional, documented
in the migration guide, and reflected in the version bump.

.. versionadded:: 1.0.16
"""

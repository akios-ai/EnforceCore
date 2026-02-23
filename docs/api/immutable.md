# Immutable — OS-Enforced Append-Only Files

::: enforcecore.auditor.immutable

## Overview

`protect_append_only()` sets the OS-level append-only attribute on audit
files, preventing truncation or overwrite even by the file owner.  This
closes the "chain rebuild" attack vector documented in the threat model
(§5.3).

This design was directly informed by guidance from Prof. Dan S. Wallach
(Rice University), who recommended `chattr +a` as a low-overhead path
from tamper detection to tamper evidence.

## Platform Support

| Platform | Method | Requirement |
|----------|--------|-------------|
| **Linux** | `chattr +a` (ioctl `FS_APPEND_FL`) | `CAP_LINUX_IMMUTABLE` capability |
| **macOS** | `chflags uappend` (`UF_APPEND`) | Root or file owner on HFS+/APFS |
| **Other** | Not supported | Logs warning, continues without protection |

### Container Considerations

Docker drops `CAP_LINUX_IMMUTABLE` by default.  You must add it explicitly:

```bash
docker run --cap-add LINUX_IMMUTABLE your-image
```

Use `platform_support_info()` to check at runtime:

```python
from enforcecore.auditor.immutable import platform_support_info

info = platform_support_info()
# {'platform': 'Linux', 'supported': True, 'in_container': True,
#  'has_capability': False, 'notes': 'Running in a container without...'}
```

## Quick Start

```python
from enforcecore.auditor.immutable import protect_append_only, is_append_only

# Protect an existing file
protect_append_only("audit.jsonl")
assert is_append_only("audit.jsonl")
```

### Via Auditor

```python
from enforcecore.auditor import Auditor

auditor = Auditor(output_path="audit.jsonl", immutable=True)
```

### Via Environment Variable (v1.0.0b5+)

```bash
export ENFORCECORE_AUDIT_IMMUTABLE=true
```

This enables append-only protection automatically when using `@enforce()`.

## Functions

| Function | Description |
|----------|-------------|
| `protect_append_only(path)` | Set the OS-level append-only attribute. Returns `True` on success. |
| `is_append_only(path)` | Check if the append-only attribute is set. |
| `platform_support_info()` | Return a dict with platform support details. |

## Exceptions

| Exception | Description |
|-----------|-------------|
| `AppendOnlyError` | Raised when protection cannot be applied (permissions, missing capabilities). |

# Witness — Hash-Only Remote Witnesses

::: enforcecore.auditor.witness

## Overview

A **witness** receives the hash of each audit entry as it is written,
enabling tamper detection even if an attacker rebuilds the Merkle chain.
Because the witness stores only hashes (~200 bytes per entry), the data
overhead is negligible.

This design was directly informed by guidance from Prof. Dan S. Wallach
(Rice University), co-author of Crosby & Wallach (2009).

## Quick Start

```python
from enforcecore.auditor import Auditor
from enforcecore.auditor.witness import CallbackWitness, verify_with_witness

# Collect witness hashes
hashes = []
witness = CallbackWitness(hashes.append)
auditor = Auditor(output_path="audit.jsonl", witness=witness)

# Record some entries
auditor.record(tool_name="search", policy_name="strict")
auditor.record(tool_name="calculator", policy_name="strict")

# Verify trail against witness
result = verify_with_witness("audit.jsonl", witness_hashes=[r.entry_hash for r in hashes])
assert result.is_valid
```

### Via Environment Variables (v1.0.0b5+)

```bash
export ENFORCECORE_AUDIT_WITNESS_FILE=/var/log/ec-witness.jsonl
```

This creates a `FileWitness` automatically when using `@enforce()`.

## Backends

### CallbackWitness

Route witness hashes to any callable — queue, HTTP endpoint, database.

```python
from enforcecore.auditor.witness import CallbackWitness

# In-memory collection
records = []
witness = CallbackWitness(records.append)

# Message queue
witness = CallbackWitness(my_queue.put)
```

!!! warning "Blocking I/O"
    The callback is invoked **synchronously** on every `record()` call.
    If it performs network I/O (HTTP POST), it adds that latency to every
    audit entry.  Wrap slow callbacks in a queue-based pattern for
    production use.

### FileWitness

Append witness hashes to a separate JSONL file.  Best when the witness
file is on a different volume or owned by a different user.

```python
from enforcecore.auditor.witness import FileWitness

witness = FileWitness("/var/log/ec-witness.jsonl")
```

### LogWitness

Emit witness hashes via Python `logging` — routes to syslog, journald,
or any configured log handler.

```python
from enforcecore.auditor.witness import LogWitness

witness = LogWitness()  # uses "enforcecore.witness" logger
```

## Verification

`verify_with_witness()` cross-checks audit trail hashes against witness
records.  If an attacker rebuilt the Merkle chain, the hashes will differ.

```python
from enforcecore.auditor.witness import verify_with_witness

# From a list of hashes
result = verify_with_witness("audit.jsonl", witness_hashes=hash_list)

# From a FileWitness file
result = verify_with_witness("audit.jsonl", witness_file="/var/log/ec-witness.jsonl")

if not result.is_valid:
    print(f"TAMPER DETECTED: {result.errors}")
```

## Classes

| Class | Description |
|-------|-------------|
| `WitnessRecord` | Frozen dataclass: `entry_id`, `entry_hash`, `previous_hash`, `sequence`, `timestamp` |
| `WitnessBackend` | ABC — implement `publish(record)` and `close()` |
| `CallbackWitness` | Sends records to a callable |
| `FileWitness` | Appends records to JSONL file |
| `LogWitness` | Emits records via Python logging |
| `WitnessVerificationResult` | Verification result: `is_valid`, `matched`, `mismatched`, `errors` |

## Functions

| Function | Description |
|----------|-------------|
| `verify_with_witness(trail_path, *, witness_hashes=, witness_file=)` | Cross-check trail against witness |

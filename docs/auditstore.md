# Auditstore: Pluggable Audit Storage

**v1.2.0 Feature**

EnforceCore's auditstore module provides pluggable audit storage with multiple backends, Merkle chain verification, and compliance query templates.

---

## Overview

The auditstore component enables:

- **Multiple storage backends** — JSONL (default), SQLite (local), PostgreSQL (production)
- **Merkle chain verification** — Tamper-evident audit trails with SHA256 hashing
- **Compliance queries** — Pre-built templates for EU AI Act, HIPAA, SOX
- **Regulatory reports** — HTML report generation for compliance audits
- **Zero breaking changes** — Backward compatible with existing Auditor API

---

## Quick Start

### Installation

Auditstore is included in EnforceCore v1.2.0+:

```bash
pip install enforcecore>=1.2.0
```

### Basic Usage

```python
from enforcecore.auditstore import AuditStore
from enforcecore.auditstore.backends import SQLiteBackend

# Create audit store with SQLite backend
backend = SQLiteBackend(db_path="audit.db")
store = AuditStore(backend=backend)

# Record an enforced call
entry = store.record(
    policy_name="agent-policy",
    policy_version="1.0",
    tool_name="search",
    decision="allowed",
    call_duration_ms=45.2,
    enforcement_overhead_ms=0.8,
    cost_usd=0.05,
)

# Retrieve entry
stored_entry = store.get_entry(entry.entry_id)

# Query entries
entries = store.list_entries(
    policy_name="agent-policy",
    tool_name="search",
    decision="allowed",
    limit=100,
)

# Verify Merkle chain
is_valid = store.verify_chain()
print(f"Chain is valid: {is_valid}")
```

---

## Backends

### JSONL Backend (Default)

**Use case:** Development, file-based storage, backward compatibility

```python
from enforcecore.auditstore.backends import JSONLBackend

backend = JSONLBackend(path="audit_logs/trail.jsonl")
store = AuditStore(backend=backend)
```

**Characteristics:**
- ✅ Works out-of-the-box
- ✅ No database required
- ✅ Human-readable JSONL format
- ✅ Single-machine deployments
- ❌ Not suitable for high-volume deployments
- ❌ No built-in querying

### SQLite Backend

**Use case:** Local development, testing, small deployments

```python
from enforcecore.auditstore.backends import SQLiteBackend

backend = SQLiteBackend(db_path="audit.db")
store = AuditStore(backend=backend)
```

**Characteristics:**
- ✅ Zero configuration
- ✅ Fast local queries
- ✅ Schema with indices
- ✅ Merkle chain verification
- ✅ Portable (single file)
- ✅ Good for up to 1M audit entries
- ⚠️ Not suitable for concurrent writes
- ❌ Limited to single machine

### PostgreSQL Backend (Coming v1.2.0)

**Use case:** Production deployments, multi-user access, high-volume auditing

```python
from enforcecore.auditstore.backends import PostgreSQLBackend

backend = PostgreSQLBackend(
    host="postgres.example.com",
    database="enforcecore_audits",
    user="enforcecore",
    password="...",
    pool_size=10,
)
store = AuditStore(backend=backend)
```

**Characteristics:**
- ✅ Enterprise-grade reliability
- ✅ Concurrent writes support
- ✅ Horizontal scalability via partitioning
- ✅ Advanced query performance
- ✅ Full Merkle chain verification
- ✅ Connection pooling
- ✅ Backup and recovery support
- ✅ Role-based access control

---

## Configuration

### Via Policy YAML

Add auditstore configuration to your policy:

```yaml
# policy.yaml
name: "production-agent"
version: "1.0"

# Audit storage configuration
auditstore:
  backend: "sqlite"      # or "jsonl", "postgresql"
  config:
    db_path: "audit.db"

rules:
  allowed_tools:
    - "search"
    - "calculator"
  denied_tools:
    - "shell"
```

### Via Python

```python
from enforcecore import enforce, Auditor
from enforcecore.auditstore.backends import SQLiteBackend

# Create auditor with auditstore
auditor = Auditor(
    backend="sqlite",
    backend_config={"db_path": "audit.db"}
)

# Use with decorator
@enforce(policy="policy.yaml")
def search(query: str) -> str:
    return api.search(query)

# Auditor will now store to SQLite instead of JSONL
```

---

## Merkle Chain Verification

The auditstore implements Merkle chain verification to ensure tamper-evidence:

### How It Works

Each audit entry is hashed with:
- Entry data (timestamp, tool name, decision, etc.)
- Parent entry's hash (creating a chain)

This creates a chain where:
- ✅ Any entry modification breaks the hash
- ✅ Any chain reordering breaks validation
- ✅ Missing entries are detected

### Verify Chain Integrity

```python
# Verify entire chain
is_valid = store.verify_chain()

# Verify range
is_valid = store.verify_chain(start_index=100, end_index=200)

# Verify single entry
entry = store.get_entry(entry_id)
is_valid = store.verify_entry(entry)

# Detect tampering
tampered_index = store.backend.detect_tampering()
if tampered_index is not None:
    print(f"Entry tampered at index: {tampered_index}")
```

### Merkle Proof

Generate cryptographic proof that an entry is in the chain:

```python
from enforcecore.auditstore.merkle import MerkleTree

entries = store.list_entries(limit=999999)
proof = MerkleTree.generate_proof(entries, target_index=42)

print(f"Target hash: {proof['target_hash']}")
print(f"Chain valid: {proof['chain_valid']}")
print(f"Position: {proof['target_index']}/{proof['chain_length']}")
```

---

## Compliance Queries

### EU AI Act (Articles 9, 13, 14, 52)

```python
from enforcecore.auditstore.queries import EUAIActQueries
from datetime import datetime, timedelta

queries = EUAIActQueries(store)
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=30)

# Article 9: High-risk decisions
article_9 = queries.article_9_high_risk_decisions(start_date, end_date)
print(f"Total decisions: {article_9['total_decisions']}")

# Article 13: Human oversight evidence
article_13 = queries.article_13_human_oversight(start_date, end_date)
print(f"Blocked calls (human oversight): {article_13['blocked_calls']}")

# Article 14: Transparency information
article_14 = queries.article_14_information_requirements(start_date, end_date)
print(f"Allowed: {article_14['statistics']['allowed_calls']}")
print(f"Blocked: {article_14['statistics']['blocked_calls']}")

# Article 52: Transparency log
article_52 = queries.article_52_transparency_log(start_date, end_date)
print(f"Merkle chain valid: {article_52['merkle_chain_verified']}")

# PII exposure summary
pii_summary = queries.pii_exposure_summary(start_date, end_date)
print(f"Total PII redactions: {pii_summary['total_pii_redactions']}")

# Policy violations summary
violations = queries.policy_violations_summary(start_date, end_date)
print(f"Total violations: {violations['total_violations']}")

# Cost analysis
costs = queries.cost_analysis(start_date, end_date)
print(f"Total cost: ${costs['total_cost_usd']}")
```

---

## Report Generation (Coming v1.2.0)

Generate compliance reports in HTML format:

```python
from enforcecore.auditstore.reports import ReportGenerator

reporter = ReportGenerator(store)

# Generate EU AI Act compliance report
report = reporter.generate_eu_ai_act_report(
    organization="ACME Corp",
    period="Q1 2026",
    format="html"
)

# Save to file
report.save("compliance_q1_2026.html")

# Or get as string
html_content = report.render()
```

Report includes:
- ✅ Article 9: All high-risk decisions
- ✅ Article 13: Human oversight evidence
- ✅ Article 14: Transparency information
- ✅ Article 52: Audit trail with Merkle verification
- ✅ Executive summary with compliance status

---

## Integration with Existing Code

The auditstore is designed to be transparent to existing EnforceCore code:

### Before (v1.1.3 - JSONL only)

```python
from enforcecore import Auditor

auditor = Auditor()  # Uses JSONL backend
# Stores to: audit_logs/trail.jsonl
```

### After (v1.2.0+ - Pluggable)

```python
from enforcecore import Auditor

# Option 1: Default (still JSONL)
auditor = Auditor()

# Option 2: SQLite
auditor = Auditor(backend="sqlite", backend_config={"db_path": "audit.db"})

# Option 3: PostgreSQL
auditor = Auditor(backend="postgresql", backend_config={
    "host": "postgres.example.com",
    "database": "audits",
    "user": "app",
    "password": "...",
})

# All three work identically with @enforce decorator
```

**Zero breaking changes** — existing code continues to work.

---

## API Reference

### AuditEntry

```python
@dataclass
class AuditEntry:
    entry_id: str                       # UUID
    timestamp: datetime                 # When the call happened
    policy_name: str                    # Policy applied
    policy_version: str                 # Policy version
    tool_name: str                      # Tool that was called
    decision: str                       # "allowed" | "blocked" | "redacted"

    # Call metrics
    call_duration_ms: float             # How long the tool took
    enforcement_overhead_ms: float      # How long enforcement took

    # PII handling
    input_redactions: int               # PII redacted from input
    output_redactions: int              # PII redacted from output
    redacted_categories: List[str]      # ["email", "phone", ...]

    # Cost tracking
    cost_usd: Optional[float]           # Tool call cost
    tokens_used: Optional[int]          # LLM tokens consumed

    # Violation details
    violation_type: Optional[str]       # "tool_denied", "policy_violation"
    violation_reason: Optional[str]     # Why it was blocked

    # Merkle chain (set by backend)
    merkle_hash: Optional[str]          # SHA256 hash
    parent_hash: Optional[str]          # Previous entry hash
    chain_index: Optional[int]          # Position in chain

    # Additional context
    context: Dict[str, Any]             # Custom metadata
```

### AuditStore

```python
class AuditStore:
    def record(**kwargs) -> AuditEntry:
        """Record a call (returns entry with Merkle hash set)"""

    def get_entry(entry_id: str) -> Optional[AuditEntry]:
        """Retrieve entry by ID"""

    def list_entries(
        policy_name: Optional[str] = None,
        tool_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        decision: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """Query entries with filters"""

    def verify_chain(
        start_index: int = 0,
        end_index: Optional[int] = None,
    ) -> bool:
        """Verify Merkle chain integrity"""

    def verify_entry(entry: AuditEntry) -> bool:
        """Verify single entry's Merkle hash"""

    def export(format: str = "jsonl") -> str:
        """Export entries for backup/migration"""
```

---

## Performance

### Typical Latencies

| Operation | SQLite | PostgreSQL |
|-----------|--------|------------|
| Record entry | < 5ms | < 10ms |
| Get entry | < 1ms | < 5ms |
| List 100 entries | 10-50ms | 20-100ms |
| Verify chain (1000 entries) | 100-200ms | 200-500ms |
| Generate report | 1-5 seconds | 2-10 seconds |

### Throughput

- **SQLite:** ~200 writes/sec, ~1000 reads/sec
- **PostgreSQL:** ~500 writes/sec, ~5000 reads/sec

---

## Backup and Migration

### Export Audit Trail

```python
# Export to JSONL
jsonl_data = store.export(format="jsonl")
with open("backup.jsonl", "w") as f:
    f.write(jsonl_data)

# Export to JSON
import json
entries = store.list_entries(limit=999999)
json_data = json.dumps([e.to_dict() for e in entries], indent=2)
```

### Migrate Backends

```python
from enforcecore.auditstore.backends import JSONLBackend, SQLiteBackend

# Read from JSONL
old_backend = JSONLBackend("audit_logs/trail.jsonl")
old_store = AuditStore(old_backend)

# Create new SQLite store
new_backend = SQLiteBackend("audit_new.db")
new_store = AuditStore(new_backend)

# Migrate entries
entries = old_store.list_entries(limit=999999)
for entry in entries:
    # Re-compute Merkle hashes for new chain
    new_store.record(**entry.to_dict())
```

---

## Troubleshooting

### SQLite: "Database is locked"

**Issue:** Multiple processes writing simultaneously

**Solutions:**
- Use PostgreSQL for concurrent writes
- Use JSONL if concurrent access not needed
- Serialize writes using a queue

### PostgreSQL: Connection refused

**Issue:** Cannot connect to database

**Check:**
```python
from enforcecore.auditstore.backends import PostgreSQLBackend

try:
    backend = PostgreSQLBackend(
        host="localhost",
        database="test",
        user="postgres",
        password="password",
    )
    print("Connection successful")
except Exception as e:
    print(f"Connection failed: {e}")
```

### Merkle verification failing

**Issue:** Chain is invalid

**Debug:**
```python
from enforcecore.auditstore.merkle import MerkleTree

entries = store.list_entries(limit=999999)
tampered_index = MerkleTree.detect_tampering(entries)

if tampered_index is not None:
    print(f"Entry tampered at index: {tampered_index}")
    print(f"Entry ID: {entries[tampered_index].entry_id}")
```

---

## Best Practices

### 1. Choose Right Backend

- **JSONL:** Development, single-machine, < 100K entries
- **SQLite:** Local development, testing, < 1M entries
- **PostgreSQL:** Production, multi-user, > 1M entries

### 2. Verify Chain Regularly

```python
# Run daily verification
is_valid = store.verify_chain()
if not is_valid:
    alert_security_team()
```

### 3. Archive Old Entries

```python
# Export old entries monthly
old_entries = store.list_entries(
    end_time=datetime.utcnow() - timedelta(days=30),
    limit=999999,
)
export_and_archive(old_entries)
```

### 4. Monitor Performance

```python
import time

start = time.time()
entries = store.list_entries(limit=10000)
latency = time.time() - start

if latency > threshold:
    optimize_database()
```

### 5. Secure PostgreSQL Connection

```python
import os

backend = PostgreSQLBackend(
    host=os.getenv("AUDIT_DB_HOST"),
    database=os.getenv("AUDIT_DB_NAME"),
    user=os.getenv("AUDIT_DB_USER"),
    password=os.getenv("AUDIT_DB_PASSWORD"),
    port=int(os.getenv("AUDIT_DB_PORT", 5432)),
)
```

---

## FAQ

**Q: Will auditstore replace the existing Auditor?**
A: No. The Auditor API remains unchanged. Auditstore is an implementation detail that Auditor can delegate to.

**Q: Can I switch backends without rewriting code?**
A: Yes. Just pass a different `backend` parameter to `Auditor()` or `AuditStore()`.

**Q: Are Merkle hashes tamper-proof?**
A: Merkle hashes detect tampering. They don't prevent it. Use with file permissions, access controls, and potentially distributed witnesses for production security.

**Q: What about HIPAA/SOX compliance?**
A: Query templates exist for both. Full support coming in v1.2.1.

**Q: Can I use auditstore outside EnforceCore?**
A: Not yet. Future versions may extract it as standalone product if demand warrants.

**Q: Performance: Which backend is fastest?**
A: SQLite for small deployments, PostgreSQL for large. JSONL is slowest but simplest.

---

## See Also

- [Enforcecore Architecture](./architecture.md)
- [Policy Configuration](./policy.md)
- [Compliance Reporting](./compliance.md)
- [API Reference](./api-design.md)

---

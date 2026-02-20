# EnforceCore — Troubleshooting

## Common Errors

### `InvalidToolNameError: Tool name contains invalid characters`

**Cause:** The tool name passed to `enforce_sync()` / `enforce_async()`
contains characters outside the allowed set.

**Allowed characters:** Word characters (`a-z`, `A-Z`, `0-9`, `_`),
dots (`.`), hyphens (`-`), colons (`:`), and angle brackets (`<`, `>`).

**Fix:** Pass a valid `tool_name` explicitly:

```python
enforcer.enforce_sync(my_func, arg, tool_name="my_tool")
```

Or rename your function to use valid characters.

---

### `InputTooLargeError: Input size exceeds limit`

**Cause:** The combined size of all string and bytes arguments exceeds
10 MB (default).

**Fix:** Reduce input size, or if you need to process large payloads,
use `check_input_size()` with a higher `max_bytes`:

```python
from enforcecore import check_input_size
check_input_size(args, kwargs, max_bytes=50 * 1024 * 1024)  # 50 MB
```

Note: The default 10 MB limit applies automatically in `enforce_sync()`
and `enforce_async()`. To change it globally, modify the constant
`MAX_INPUT_SIZE_BYTES` or subclass `Enforcer`.

---

### `EnforcementDepthError: Enforcement nesting depth exceeds maximum`

**Cause:** An enforced tool called another enforced tool, and the nesting
exceeded the maximum depth (default: 10).

**Fix:** Check for recursive enforcement chains. The error message includes
the call chain for debugging:

```
Call chain: tool_a -> tool_b -> tool_c -> ... -> tool_a
```

If legitimate deep nesting is needed, increase the `max_depth` parameter:

```python
from enforcecore import enter_enforcement
enter_enforcement("my_tool", max_depth=20)
```

---

### `ToolDeniedError: Tool not in allowed list`

**Cause:** The policy does not allow the tool being called.

**Fix:** Add the tool name to `allowed_tools` in your policy YAML:

```yaml
rules:
  allowed_tools:
    - "search_web"
    - "your_tool_name"  # Add this
```

Or remove `denied_tools` restrictions if they apply.

---

### `CostLimitError: Cumulative cost exceeds budget`

**Cause:** The total cost recorded via `enforcer.record_cost()` exceeded
the budget configured in `resource_limits.max_cost_usd` or the global
`ENFORCECORE_COST_BUDGET_USD`.

**Fix:** Increase the budget, or reset the cost tracker:

```python
enforcer.guard.cost_tracker.reset()
```

---

### `ResourceLimitError: Call duration exceeded`

**Cause:** A tool call exceeded the time limit configured in the policy's
`resource_limits.max_call_duration_seconds`.

**Fix:** Increase the time limit in your policy:

```yaml
rules:
  resource_limits:
    max_call_duration_seconds: 60  # Increase from default
```

Or optimize the tool to run faster.

---

### `RuntimeWarning: fail_open is enabled without ENFORCECORE_DEV_MODE=1`

**Cause:** `fail_open=True` is set in the configuration, but the
`ENFORCECORE_DEV_MODE` environment variable is not set.

**Fix:** Either:

1. **Disable fail_open** (recommended for production):
   ```bash
   ENFORCECORE_FAIL_OPEN=false
   ```

2. **Acknowledge dev mode** (development only):
   ```bash
   ENFORCECORE_DEV_MODE=1
   ```

---

### `UserWarning: guard_sync() only performs pre-call policy checks`

**Cause:** You are using `guard_sync()` or `guard_async()` which only
perform pre-call checks. They do NOT redact PII, enforce resource limits,
or record audit entries.

**Fix:** Use `enforce_sync()` / `enforce_async()` for full protection:

```python
# Instead of this:
with enforcer.guard_sync("my_tool") as ctx:
    result = do_something()

# Do this:
result = enforcer.enforce_sync(do_something, tool_name="my_tool")
```

---

### `PolicyLoadError: No policy provided`

**Cause:** `@enforce` was used without arguments and no default policy
is configured.

**Fix:** Either pass a policy explicitly:

```python
@enforce(policy="policy.yaml")
def my_tool(): ...
```

Or set a default policy:

```bash
ENFORCECORE_DEFAULT_POLICY=policies/default.yaml
```

---

### `RedactionError: Unknown PII category`

**Cause:** An unrecognized PII category was passed to the `Redactor`.

**Supported categories:** `email`, `phone`, `ssn`, `credit_card`,
`ip_address`, `person_name`.

**Fix:** Use one of the supported categories:

```python
redactor = Redactor(categories=["email", "phone"])
```

---

## Debugging Tips

### Enable debug logging

```bash
ENFORCECORE_LOG_LEVEL=DEBUG
```

This shows detailed structured logs for every enforcement decision,
redaction event, and audit entry.

### Check enforcement scope

```python
from enforcecore import get_enforcement_depth, get_enforcement_chain

print(f"Depth: {get_enforcement_depth()}")
print(f"Chain: {get_enforcement_chain()}")
```

### Verify audit trail integrity

```python
from enforcecore import verify_trail

result = verify_trail("audit.jsonl")
if not result.is_valid:
    for error in result.errors:
        print(f"  ERROR: {error}")
```

### Test your policy

```python
from enforcecore.eval import ScenarioRunner
from enforcecore.core.policy import Policy

policy = Policy.from_file("policy.yaml")
runner = ScenarioRunner(policy)
suite = runner.run_all()
print(f"Containment rate: {suite.containment_rate:.0%}")
```

---

## Platform Notes

### macOS

Memory limits use `RLIMIT_RSS` which is advisory (not strictly enforced
by the kernel). Time limits and cost tracking work fully.

### Windows

Memory limits are not available. Time limits, cost tracking, and all
other features work fully.

### Linux

Full support for all features including strict memory limits via
`RLIMIT_AS`.

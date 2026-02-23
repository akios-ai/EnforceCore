"""Post-release pip install test for enforcecore==1.0.0b1."""

import sys

passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"[PASS] {name}")
        passed += 1
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        failed += 1


# Test 0: Version check
def t0():
    import enforcecore

    assert enforcecore.__version__ == "1.0.0b1", f"Got {enforcecore.__version__}"
    assert len(enforcecore.__all__) == 30, f"Got {len(enforcecore.__all__)}"


test("Version and API surface (30 symbols, beta)", t0)


# Test 1: Policy loading
def t1():
    from enforcecore import Policy

    p = Policy.from_dict(
        {
            "name": "pip-test",
            "rules": {"allowed_tools": ["read_file", "search"], "denied_tools": ["delete_file"]},
        }
    )
    assert p.name == "pip-test"


test("Policy.from_dict", t1)


# Test 2: Enforcement decorator (allow)
def t2():
    from enforcecore import Policy, enforce

    p = Policy.from_dict({"name": "t2", "rules": {"allowed_tools": ["read_file"]}})

    @enforce(policy=p)
    def read_file(path: str) -> str:
        return f"contents of {path}"

    result = read_file(path="test.txt")
    assert "contents of test.txt" in result


test("@enforce allows permitted tool", t2)


# Test 3: Enforcement decorator (deny)
def t3():
    from enforcecore import Policy, enforce
    from enforcecore.core.types import ToolDeniedError

    p = Policy.from_dict(
        {"name": "t3", "rules": {"allowed_tools": ["search"], "denied_tools": ["delete_file"]}}
    )

    @enforce(policy=p)
    def delete_file(path: str) -> str:
        return "deleted"

    try:
        delete_file(path="important.txt")
        msg = "Should have raised ToolDeniedError"
        raise AssertionError(msg)
    except ToolDeniedError:
        pass


test("@enforce denies blocked tool", t3)


# Test 4: PII redaction
def t4():
    from enforcecore import Redactor

    r = Redactor()
    result = r.redact("Contact john@example.com or call 555-123-4567")
    assert "john@example.com" not in result.text


test("Redactor PII detection", t4)


# Test 5: Secret scanning
def t5():
    from enforcecore.redactor.secrets import SecretScanner

    s = SecretScanner()
    findings = s.detect("AKIAIOSFODNN7EXAMPLE key found here")
    assert len(findings) >= 1


test("SecretScanner AWS key detection", t5)


# Test 6: Audit trail
def t6():
    import os
    import tempfile

    from enforcecore import Auditor, verify_trail

    with tempfile.TemporaryDirectory() as td:
        trail = os.path.join(td, "trail.jsonl")
        a = Auditor(output_path=trail)
        a.record(tool_name="test", decision="allowed", policy_name="pip-test")
        result = verify_trail(trail)
        assert result.is_valid is True
        assert result.chain_intact is True


test("Auditor Merkle-chain verification", t6)


# Test 7: Content rules
def t7():
    from enforcecore.core.rules import RuleEngine

    engine = RuleEngine.with_builtins()
    assert engine.rule_count >= 4
    violations = engine.check("please run rm -rf /")
    assert len(violations) > 0


test("RuleEngine builtin pattern blocking", t7)


# Test 8: Rate limiter
def t8():
    from enforcecore.guard.ratelimit import RateLimiter

    rl = RateLimiter()
    # just instantiation test - API check
    assert rl is not None


test("RateLimiter instantiation", t8)


# Test 9: Network guard
def t9():
    from enforcecore.guard.network import DomainChecker

    dc = DomainChecker(allowed_domains=["example.com"])
    assert dc.is_domain_allowed("example.com") is True
    assert dc.is_domain_allowed("evil.com") is False


test("DomainChecker allow/deny", t9)


# Test 10: Enforcer class
def t10():
    from enforcecore import Enforcer, Policy

    p = Policy.from_dict({"name": "t10", "rules": {"allowed_tools": ["search"]}})
    e = Enforcer(policy=p)
    assert e is not None


test("Enforcer class instantiation", t10)


# Test 11: Eval scenarios
def t11():
    from enforcecore.eval.scenarios import get_all_scenarios

    scenarios = get_all_scenarios()
    assert len(scenarios) >= 20


test("Eval scenarios loaded", t11)


# Test 12: Framework integrations
def t12():
    from enforcecore.integrations import autogen, crewai, langgraph  # noqa: F401


test("Integrations importable", t12)

print()
print("=" * 55)
print(f"RESULTS: {passed} passed, {failed} failed")
print("Package: enforcecore==1.0.0b1 from PyPI")
print("=" * 55)
sys.exit(1 if failed else 0)

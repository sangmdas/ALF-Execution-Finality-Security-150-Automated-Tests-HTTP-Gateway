"""Exactly 13 independent illustrative laboratory assertions/scenarios."""
from dataclasses import replace
import pytest
from alf_reference import ActivationController, ApprovalRegistry, Validator, FinalitySink, Operation, Denied

@pytest.fixture
def lab():
    controller = ActivationController({"ranker": "rank-v1", "features": "feat-v1"})
    registry = ApprovalRegistry({"ranker": "rank-v1", "features": "feat-v1"})
    validator = Validator(controller, registry, b"test-receipt-key", b"test-enablement-key")
    sink = FinalitySink(controller, registry, b"test-receipt-key", b"test-enablement-key")
    op = Operation("op-1", "ranked-posts:a,b,c", "feed:user-7")
    return controller, registry, validator, sink, op

# T01: correctly authorized operation reaches sink

def test_01_authorized_release(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    assert s.release(op, receipt, cap, now=101) == "RELEASED:op-1"

# T02: unapproved ranker detected before receipt issuance

def test_02_model_generation_mismatch_before_receipt(lab):
    c, r, v, s, op = lab
    c.hot_swap("ranker", "rank-v2")
    with pytest.raises(Denied, match="not approved"):
        v.validate(op, now=100)

# T03: configuration hot swap after receipt, before effect

def test_03_config_hot_swap_after_receipt(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    c.hot_swap("features", "feat-v2")
    with pytest.raises(Denied, match="hot-swap"):
        s.release(op, receipt, cap, now=101)

# T04: even hot-swap to SAME configuration bumps protected generation

def test_04_same_config_new_generation_invalidates_receipt(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    c.hot_swap("ranker", "rank-v1")
    with pytest.raises(Denied, match="generation mismatch"):
        s.release(op, receipt, cap, now=101)

# T05: alternate actual output cannot be substituted

def test_05_output_substitution(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    different = replace(op, output="ranked-posts:c,b,a")
    with pytest.raises(Denied, match="actual operation"):
        s.release(different, receipt, cap, now=101)

# T06: recipient change cannot use the approved operation

def test_06_destination_substitution(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    with pytest.raises(Denied, match="actual operation"):
        s.release(replace(op, destination="feed:user-99"), receipt, cap, now=101)

# T07: receipt alone never sufficient

def test_07_receipt_without_enablement(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    with pytest.raises(Denied, match="missing enablement"):
        s.release(op, receipt, None, now=101)

# T08: altered authenticated receipt rejected

def test_08_tampered_receipt(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    with pytest.raises(Denied, match="receipt authentication"):
        s.release(op, replace(receipt, expires_at=10000), cap, now=101)

# T09: altered scoped capability rejected

def test_09_tampered_enablement(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    with pytest.raises(Denied, match="enablement authentication"):
        s.release(op, receipt, replace(cap, operation_commitment="forgery"), now=101)

# T10: wrong sink not allowed

def test_10_wrong_finality_sink(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    other_sink = FinalitySink(c, r, b"test-receipt-key", b"test-enablement-key", sink_name="other-gateway")
    with pytest.raises(Denied, match="wrong sink"):
        other_sink.release(op, receipt, cap, now=101)

# T11: expired receipt rejected

def test_11_expired_receipt(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, ttl=5, now=100)
    with pytest.raises(Denied, match="expired"):
        s.release(op, receipt, cap, now=106)

# T12: policy epoch revocation invalidates outstanding authorization

def test_12_revocation(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    r.revoke()
    with pytest.raises(Denied, match="revoked"):
        s.release(op, receipt, cap, now=101)

# T13: consuming same authorization twice rejected

def test_13_replay_prevention(lab):
    c, r, v, s, op = lab
    receipt, cap = v.validate(op, now=100)
    assert s.release(op, receipt, cap, now=101) == "RELEASED:op-1"
    with pytest.raises(Denied, match="already consumed"):
        s.release(op, receipt, cap, now=102)

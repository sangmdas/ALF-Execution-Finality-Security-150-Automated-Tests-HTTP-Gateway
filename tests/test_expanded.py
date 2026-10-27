"""125 generated, individually named scenarios across eight security categories.
Each parameter is a separately collected pytest test; no probabilistic claims.
"""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import pytest
from alf_reference import ActivationController, ApprovalRegistry, Validator, FinalitySink, Operation, Denied

@pytest.fixture
def env():
    c=ActivationController({'ranker':'rank-v1','features':'feat-v1'})
    r=ApprovalRegistry({'ranker':'rank-v1','features':'feat-v1'})
    v=Validator(c,r,b'receipt-key',b'enablement-key')
    s=FinalitySink(c,r,b'receipt-key',b'enablement-key')
    op=Operation('op-1','ranked-posts:a,b,c','feed:user-7')
    return c,r,v,s,op

# 25 distinct alterations to the actual output descriptor/recipient/identifier.
@pytest.mark.parametrize('variant', range(25),ids=lambda x:f'actual-op-mutation-{x:02d}')
def test_unauthorized_actual_operation_mutations(env,variant):
    c,r,v,s,op=env
    rec,cap=v.validate(op,now=100)
    if variant<10:
        altered=replace(op,output=f'ranked-posts:a,b,{variant}')
    elif variant<20:
        altered=replace(op,destination=f'feed:user-{variant}')
    else:
        altered=replace(op,operation_id=f'op-{variant}')
    with pytest.raises(Denied, match='actual operation'):
        s.release(altered,rec,cap,now=101)

# 16 variants exercising different stage/config substitutions before approval.
@pytest.mark.parametrize('variant',range(16),ids=lambda x:f'unapproved-stage-config-{x:02d}')
def test_unapproved_config_prevalidation(env,variant):
    c,r,v,s,op=env
    stage='ranker' if variant%2==0 else 'features'
    c.hot_swap(stage,f'unknown-config-{variant}')
    with pytest.raises(Denied, match='not approved'):
        v.validate(op,now=100)

# 16 variants exercising generation changes *after* issuance, with unchanged config ID.
@pytest.mark.parametrize('variant',range(16),ids=lambda x:f'same-config-generation-{x:02d}')
def test_generation_after_validation(env,variant):
    c,r,v,s,op=env
    rec,cap=v.validate(op,now=100)
    stage='ranker' if variant%2==0 else 'features'
    for _ in range(1+variant//2):
        c.hot_swap(stage,'rank-v1' if stage=='ranker' else 'feat-v1')
    with pytest.raises(Denied,match='generation mismatch'):
        s.release(op,rec,cap,now=101)

# 15 changes to signed receipt fields; all must fail authentication.
@pytest.mark.parametrize('variant',range(15),ids=lambda x:f'receipt-authentication-{x:02d}')
def test_tampered_receipt_variants(env,variant):
    c,r,v,s,op=env
    rec,cap=v.validate(op,now=100)
    field=('receipt_id','alf_i','alf_e','alf_o','policy_epoch','sink','expires_at')[variant%7]
    current=getattr(rec,field)
    altered=replace(rec,**{field:current+1 if isinstance(current,int) else current+f'-tampered-{variant}'})
    with pytest.raises(Denied,match='receipt authentication'):
        s.release(op,altered,cap,now=101)

# 15 modifications to enablement fields; each must fail authentication.
@pytest.mark.parametrize('variant',range(15),ids=lambda x:f'enablement-authentication-{x:02d}')
def test_tampered_enablement_variants(env,variant):
    c,r,v,s,op=env
    rec,cap=v.validate(op,now=100)
    field=('receipt_id','operation_commitment','sink','epoch')[variant%4]
    current=getattr(cap,field)
    altered=replace(cap,**{field:current+1 if isinstance(current,int) else current+f'-tampered-{variant}'})
    with pytest.raises(Denied,match='enablement authentication'):
        s.release(op,rec,altered,now=101)

# 12 variations of revocation, epoch update, and expiry.
@pytest.mark.parametrize('variant',range(12),ids=lambda x:f'policy-validity-{x:02d}')
def test_policy_state_expiry_variants(env,variant):
    c,r,v,s,op=env
    rec,cap=v.validate(op,ttl=2+variant,now=100)
    if variant<4:
        r.revoke()
        expected='revoked'
        now=101
    elif variant<8:
        for _ in range(variant-3):
            r.advance_epoch()
        expected='revoked'
        now=101
    else:
        expected='expired'
        now=rec.expires_at+1+variant
    with pytest.raises(Denied,match=expected):
        s.release(op,rec,cap,now=now)

# 14 concurrent claimants; exactly one release succeeds in the simulated sink.
@pytest.mark.parametrize('workers',range(2,16),ids=lambda x:f'concurrent-{x:02d}-workers')
def test_atomic_single_consumption(env,workers):
    c,r,v,s,op=env
    rec,cap=v.validate(op,now=100)
    def attempt(_):
        try:
            return s.release(op,rec,cap,now=101)
        except Denied:
            return 'WITHHELD'
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results=list(pool.map(attempt,range(workers)))
    assert results.count('RELEASED:op-1')==1
    assert results.count('WITHHELD')==workers-1

# 12 sink substitutions, including mismatched destination in authorized operation.
@pytest.mark.parametrize('variant',range(12),ids=lambda x:f'sink-binding-{x:02d}')
def test_sink_binding(env,variant):
    c,r,v,s,op=env
    rec,cap=v.validate(op,now=100)
    other=FinalitySink(c,r,b'receipt-key',b'enablement-key',sink_name=f'other-sink-{variant}')
    with pytest.raises(Denied,match='wrong sink'):
        other.release(op,rec,cap,now=101)

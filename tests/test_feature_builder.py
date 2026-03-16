import time, sys, math
sys.path.insert(0, '.')
from falco.feature_builder import FeatureWindowBuilder, EntityWindow
import joblib
from pathlib import Path

MODELS_DIR = Path('models')

def make_raw(rule='', evt='read', proc='bash', pid=100, ppid=1, user='root'):
    return {
        'rule': rule, 'evt_type': evt,
        'proc_name': proc, 'proc_pid': pid,
        'proc_ppid': ppid, 'user_name': user,
        'timestamp': time.time()
    }

# ── Test 1: Window closes after timeout ──────────────────────────
def test_window_closes_after_timeout():
    b = FeatureWindowBuilder(window_seconds=0.1)
    b.ingest(make_raw())
    time.sleep(0.15)
    vecs = b.ingest(make_raw())
    assert len(vecs) == 1, f'Expected 1 vector after timeout, got {len(vecs)}'
    print('PASS: window closes and emits vector after timeout')

# ── Test 2: No vector before timeout ─────────────────────────────
def test_no_vector_before_timeout():
    b = FeatureWindowBuilder(window_seconds=10)
    for _ in range(5):
        vecs = b.ingest(make_raw())
        assert len(vecs) == 0, 'Vector emitted before window closed'
    print('PASS: no vector emitted before window timeout')

# ── Test 3: All 14 required feature keys present ─────────────────
def test_all_required_feature_keys():
    if not (MODELS_DIR / 'host_feature_cols.pkl').exists():
        # Fallback: check against known schema
        required = [
            'process_spawn_rate', 'file_access_rate', 'net_activity_rate',
            'process_chain_depth', 'priv_escalation_count', 'inject_attempt_count',
            'mmap_count', 'syscall_entropy', 'unique_syscall_ratio', 'repeat_ratio',
            'trace_length', 'rule_outbound', 'rule_priv_esc', 'rule_sensitive_file'
        ]
    else:
        required = joblib.load(MODELS_DIR / 'host_feature_cols.pkl')

    b = FeatureWindowBuilder(window_seconds=0.05)
    b.ingest(make_raw())
    time.sleep(0.08)
    vecs = b.ingest(make_raw())
    hf = vecs[0]['host_features']
    missing = [k for k in required if k not in hf]
    assert not missing, f'Missing feature keys: {missing}'
    extra = [k for k in hf if k not in required]
    assert not extra, f'Extra unexpected keys: {extra}'
    print(f'PASS: all {len(required)} feature keys present, no extras')

# ── Test 4: Rates bounded [0, 1] ─────────────────────────────────
def test_rates_bounded():
    b = FeatureWindowBuilder(window_seconds=0.05)
    for evt in ['connect','setuid','ptrace','open','clone','mmap'] * 5:
        b.ingest(make_raw(evt=evt))
    time.sleep(0.08)
    vecs = b.ingest(make_raw())
    hf = vecs[0]['host_features']
    for key in ['process_spawn_rate','file_access_rate','net_activity_rate',
                'unique_syscall_ratio','repeat_ratio']:
        assert 0 <= hf[key] <= 1, f'{key}={hf[key]} out of [0,1]'
    print('PASS: all rate features bounded in [0, 1]')

# ── Test 5: Entropy non-negative ─────────────────────────────────
def test_entropy_non_negative():
    b = FeatureWindowBuilder(window_seconds=0.05)
    for proc in ['bash','python','nginx','curl','sh']:
        b.ingest(make_raw(proc=proc))
    time.sleep(0.08)
    vecs = b.ingest(make_raw())
    assert vecs[0]['host_features']['syscall_entropy'] >= 0
    print('PASS: syscall_entropy >= 0')

# ── Test 6: Entity isolation ──────────────────────────────────────
def test_entity_isolation():
    b = FeatureWindowBuilder(window_seconds=0.08)
    # Attacker entity fires OUTBOUND rule
    b.ingest(make_raw(rule='CyberShield Outbound Connection', user='attacker', proc='bash'))
    # Benign entity has no rules
    b.ingest(make_raw(user='normal', proc='nginx'))
    time.sleep(0.1)
    # Trigger flush for both entities
    b.ingest(make_raw(user='attacker', proc='bash'))
    all_vecs = b.ingest(make_raw(user='normal', proc='nginx'))
    # Find benign entity's vector
    benign = [v for v in all_vecs if 'normal' in v['entity_id']]
    if benign:
        assert benign[0]['host_features']['rule_outbound'] == 0, \
            'Benign entity incorrectly got rule_outbound=1 from attacker window'
    print('PASS: entity isolation — attacker flags do not bleed into benign entity')

# ── Test 7: force_flush emits all open windows ────────────────────
def test_force_flush():
    b = FeatureWindowBuilder(window_seconds=60)  # long window
    for user in ['a', 'b', 'c']:
        b.ingest(make_raw(user=user))
    vecs = b.force_flush()
    assert len(vecs) == 3, f'Expected 3 vectors from force_flush, got {len(vecs)}'
    assert len(b.windows) == 0, 'Windows not cleared after force_flush'
    print('PASS: force_flush emits all 3 open windows and clears state')

# ── Test 8: Process chain depth tracking ─────────────────────────
def test_chain_depth_increases():
    b = FeatureWindowBuilder(window_seconds=0.05)
    # Simulate: init(pid=1) → bash(pid=10) → python(pid=20) → curl(pid=30)
    b.ingest(make_raw(evt='clone', proc='bash',   pid=10, ppid=1))
    b.ingest(make_raw(evt='execve',proc='python', pid=20, ppid=10))
    b.ingest(make_raw(evt='execve',proc='curl',   pid=30, ppid=20))
    time.sleep(0.08)
    vecs = b.ingest(make_raw())
    depth = vecs[0]['host_features']['process_chain_depth']
    assert depth >= 2, f'Chain depth should be >= 2 for 3-level chain, got {depth}'
    print(f'PASS: process_chain_depth = {depth} for 3-level chain')

if __name__ == '__main__':
    test_window_closes_after_timeout()
    test_no_vector_before_timeout()
    test_all_required_feature_keys()
    test_rates_bounded()
    test_entropy_non_negative()
    test_entity_isolation()
    test_force_flush()
    test_chain_depth_increases()
    print('\nAll feature_builder tests passed.')

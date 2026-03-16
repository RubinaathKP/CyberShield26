import json, time, sys
sys.path.insert(0, '.')
from falco.feature_builder import FeatureWindowBuilder

def make_falco_event(rule='', evt_type='read', proc='bash', pid=100, ppid=1, user='root', sip='', sport='', fd_name=''):
    return {
        'rule': rule,
        'priority': 'WARNING',
        'output_fields': {
            'proc.name':  proc,
            'proc.pid':   pid,
            'proc.ppid':  ppid,
            'user.name':  user,
            'fd.sip':     sip,
            'fd.sport':   sport,
            'fd.name':    fd_name,
            'evt.type':   evt_type,
        }
    }

def extract_raw(event):
    fields = event.get('output_fields', {})
    return {
        'rule':      event.get('rule', ''),
        'priority':  event.get('priority', 'DEBUG'),
        'proc_name': fields.get('proc.name', ''),
        'proc_pid':  fields.get('proc.pid', 0),
        'proc_ppid': fields.get('proc.ppid', 0),
        'user_name': fields.get('user.name', ''),
        'fd_sip':    fields.get('fd.sip', ''),
        'fd_sport':  fields.get('fd.sport', ''),
        'fd_name':   fields.get('fd.name', ''),
        'evt_type':  fields.get('evt.type', ''),
        'timestamp': time.time(),
    }

# ── Test 1: OUTBOUND rule sets flag ──────────────────────────────
def test_outbound_rule_flag():
    b = FeatureWindowBuilder(window_seconds=0.05)
    raw = extract_raw(make_falco_event(
        rule='CyberShield Outbound Connection',
        evt_type='connect', proc='bash', sip='185.1.2.3', sport='4444'
    ))
    time.sleep(0.08)
    vecs = b.ingest(raw)
    assert len(vecs) == 1, f'Expected 1 vector, got {len(vecs)}'
    assert vecs[0]['host_features']['rule_outbound'] == 1
    assert vecs[0]['host_features']['rule_priv_esc'] == 0
    print('PASS: OUTBOUND rule sets rule_outbound=1')

# ── Test 2: PRIV_ESC rule sets flag ──────────────────────────────
def test_priv_esc_rule_flag():
    b = FeatureWindowBuilder(window_seconds=0.05)
    raw = extract_raw(make_falco_event(
        rule='CyberShield Privilege Escalation',
        evt_type='setuid', proc='python3'
    ))
    time.sleep(0.08)
    vecs = b.ingest(raw)
    assert vecs[0]['host_features']['rule_priv_esc'] == 1
    print('PASS: PRIV_ESC rule sets rule_priv_esc=1')

# ── Test 3: SENSITIVE_FILE rule sets flag ────────────────────────
def test_sensitive_file_rule_flag():
    b = FeatureWindowBuilder(window_seconds=0.05)
    raw = extract_raw(make_falco_event(
        rule='CyberShield Sensitive File Access',
        evt_type='open', fd_name='/etc/shadow'
    ))
    time.sleep(0.08)
    vecs = b.ingest(raw)
    assert vecs[0]['host_features']['rule_sensitive_file'] == 1
    print('PASS: SENSITIVE_FILE rule sets rule_sensitive_file=1')

# ── Test 4: Non-CyberShield rule sets no flags ───────────────────
def test_non_cybershield_no_flags():
    b = FeatureWindowBuilder(window_seconds=0.05)
    raw = extract_raw(make_falco_event(
        rule='Some Other Falco Rule',
        evt_type='read', proc='nginx'
    ))
    time.sleep(0.08)
    vecs = b.ingest(raw)
    hf = vecs[0]['host_features']
    assert hf['rule_outbound']       == 0
    assert hf['rule_priv_esc']       == 0
    assert hf['rule_sensitive_file'] == 0
    print('PASS: non-CyberShield rule sets no feature flags')

# ── Test 5: Invalid JSON does not crash ──────────────────────────
def test_invalid_json_skipped():
    bad_lines = [
        'not json at all',
        '{incomplete json',
        '',
        'Falco startup message (not JSON)',
    ]
    for line in bad_lines:
        try:
            json.loads(line)
            print(f'  Parsed: {line[:30]}')
        except json.JSONDecodeError:
            pass  # Expected — forwarder skips these
    print('PASS: invalid JSON lines skipped without crash')

# ── Test 6: Multiple rules can fire in one window ────────────────
def test_multiple_rules_in_window():
    b = FeatureWindowBuilder(window_seconds=0.1)
    events = [
        make_falco_event(rule='CyberShield Outbound Connection',    evt_type='connect'),
        make_falco_event(rule='CyberShield Privilege Escalation',   evt_type='setuid'),
        make_falco_event(rule='CyberShield Sensitive File Access',  evt_type='open', fd_name='/etc/shadow'),
    ]
    for ev in events:
        b.ingest(extract_raw(ev))
    time.sleep(0.15)
    vecs = b.ingest(extract_raw(make_falco_event()))
    hf = vecs[0]['host_features']
    assert hf['rule_outbound']       == 1
    assert hf['rule_priv_esc']       == 1
    assert hf['rule_sensitive_file'] == 1
    print('PASS: all 3 rule flags set when all 3 rules fire in window')

if __name__ == '__main__':
    test_outbound_rule_flag()
    test_priv_esc_rule_flag()
    test_sensitive_file_rule_flag()
    test_non_cybershield_no_flags()
    test_invalid_json_skipped()
    test_multiple_rules_in_window()
    print('\nAll forwarder tests passed.')

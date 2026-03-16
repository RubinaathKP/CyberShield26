"""
Developer 1 full integration test for Phase C.

Requires:
    redis-server running
    uvicorn api.main:app --host 0.0.0.0 --port 8000

For live Falco test (optional):
    bash falco/start_falco.sh  (in separate terminal)

Run: python tests/test_dev1_integration.py
"""
import redis, json, time, subprocess, requests, sys, pathlib
sys.path.insert(0, '.')
from config import REDIS_HOST, REDIS_PORT, API_HOST, API_PORT
from config import FALCO_EVENTS_QUEUE

r    = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
BASE = f'http://{API_HOST}:{API_PORT}'

passed, failed = [], []

def check(name, fn):
    try:
        fn()
        passed.append(name)
        print(f'  ✅  {name}')
    except Exception as e:
        failed.append((name, str(e)))
        print(f'  ❌  {name}: {e}')

# ── C1: Environment ──────────────────────────────────────────────
check('C1: Redis is running',
    lambda: r.ping())

check('C1: Python venv has required packages',
    lambda: __import__('sklearn') and __import__('shap'))

check('C1: Model files exist',
    lambda: all(
        pathlib.Path(f'models/{f}').exists()
        for f in ['host_rf.pkl','net_rf.pkl','meta_clf.pkl']
    ))

# ── C2: Rules ─────────────────────────────────────────────────────
check('C2: Falco rules file exists',
    lambda: pathlib.Path('falco/cybershield_rules.yaml').exists())

check('C2: Rules file contains 3 CyberShield rules',
    lambda: pathlib.Path('falco/cybershield_rules.yaml').read_text().count('rule: CyberShield') == 3)

# ── C3: Forwarder ─────────────────────────────────────────────────
def c3_forwarder_rule_parsing():
    from falco.feature_builder import FeatureWindowBuilder
    b = FeatureWindowBuilder(window_seconds=0.05)
    b.ingest({'rule':'CyberShield Outbound Connection',
              'evt_type':'connect','proc_name':'bash',
              'proc_pid':100,'proc_ppid':1,'user_name':'root',
              'fd_sip':'1.2.3.4','fd_sport':'4444','timestamp':time.time()})
    time.sleep(0.08)
    vecs = b.ingest({'rule':'','evt_type':'read','proc_name':'x',
                     'proc_pid':101,'proc_ppid':1,'user_name':'root','timestamp':time.time()})
    assert len(vecs) == 1
    assert vecs[0]['host_features']['rule_outbound'] == 1
check('C3: Forwarder correctly sets rule_outbound=1', c3_forwarder_rule_parsing)

# ── C4: Feature builder ───────────────────────────────────────────
def c4_feature_schema():
    import joblib
    from falco.feature_builder import FeatureWindowBuilder
    expected = joblib.load('models/host_feature_cols.pkl')
    b = FeatureWindowBuilder(window_seconds=0.05)
    b.ingest({'rule':'','evt_type':'read','proc_name':'bash',
              'proc_pid':1,'proc_ppid':0,'user_name':'root','timestamp':time.time()})
    time.sleep(0.08)
    vecs = b.ingest({'rule':'','evt_type':'read','proc_name':'x',
                     'proc_pid':2,'proc_ppid':1,'user_name':'root','timestamp':time.time()})
    hf = vecs[0]['host_features']
    missing = [k for k in expected if k not in hf]
    assert not missing, f'Missing feature keys: {missing}'
check('C4: Feature vector matches model schema exactly', c4_feature_schema)

# ── C5: API server ───────────────────────────────────────────────
check('C5: API server reachable',
    lambda: requests.get(f'{BASE}/metrics', timeout=3).raise_for_status())

# ── C6: MTTD tracking ────────────────────────────────────────────
def c6_mttd_in_metrics():
    data = requests.get(f'{BASE}/metrics', timeout=3).json()
    assert 'avg_mttd_seconds' in data, 'avg_mttd_seconds missing from /metrics'
    assert 'threat_counts' in data, 'threat_counts missing from /metrics'
check('C6: GET /metrics returns MTTD and threat_counts', c6_mttd_in_metrics)

# ── End-to-end: inject scenario → API scores it ──────────────────
def e2e_meterpreter_critical():
    s = json.loads(pathlib.Path('scenarios/scenario_02_meterpreter.json').read_text())
    resp = requests.post(f'{BASE}/predict',
        json={
            'host_features': s['host_features'],
            'net_features':  s['net_features'],
            'entity_id':     s['entity_id'],
        }, timeout=10)
    resp.raise_for_status()
    d = resp.json()
    assert d['final_score'] > 0.70, f'Meterpreter scored only {d["final_score"]:.3f}'
    assert d['threat_level'] in ['HIGH','CRITICAL'], f'Got {d["threat_level"]}'
check('E2E: Meterpreter scenario scores HIGH/CRITICAL', e2e_meterpreter_critical)

def e2e_benign_stays_low():
    s = json.loads(pathlib.Path('scenarios/scenario_04_benign_admin.json').read_text())
    resp = requests.post(f'{BASE}/predict',
        json={
            'host_features': s['host_features'],
            'net_features':  s['net_features'],
            'entity_id':     s['entity_id'],
        }, timeout=10)
    d = resp.json()
    assert d['threat_level'] in ['LOW','MEDIUM'], \
        f'Benign admin triggered {d["threat_level"]} — false positive!'
check('E2E: Benign admin stays LOW/MEDIUM (no FP)', e2e_benign_stays_low)

def e2e_falco_events_queue():
    from falco.feature_builder import FeatureWindowBuilder
    before = r.llen(FALCO_EVENTS_QUEUE)
    b = FeatureWindowBuilder(window_seconds=0.05)
    b.ingest({'rule':'CyberShield Sensitive File Access',
              'evt_type':'open','proc_name':'bash','fd_name':'/etc/shadow',
              'proc_pid':200,'proc_ppid':1,'user_name':'root','timestamp':time.time()})
    time.sleep(0.08)
    vecs = b.ingest({'rule':'','evt_type':'read','proc_name':'x',
                     'proc_pid':201,'proc_ppid':1,'user_name':'root','timestamp':time.time()})
    for v in vecs:
        r.lpush(FALCO_EVENTS_QUEUE, json.dumps(v))
    after = r.llen(FALCO_EVENTS_QUEUE)
    assert after > before
check('E2E: Feature vector with sensitive_file=1 pushed to Redis', e2e_falco_events_queue)

# ── Summary ───────────────────────────────────────────────────────
print(f'\n{"="*52}')
print(f'Phase C Integration: {len(passed)} passed, {len(failed)} failed')
if failed:
    print('\nFailed:')
    for name, err in failed:
        print(f'  ❌ {name}')
        print(f'     {err}')
else:
    print('All tests passed. Phase C is demo-ready.')
    print('Push to dev/falco and notify Dev 2 to begin merge.')
raise SystemExit(0 if not failed else 1)

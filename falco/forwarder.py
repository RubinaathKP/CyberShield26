import sys
import json
import time
import redis
sys.path.insert(0, '/root/cybershield')
from config import REDIS_HOST, REDIS_PORT, FALCO_EVENTS_QUEUE
from falco.feature_builder import FeatureWindowBuilder

# ── Redis connection ──────────────────────────────────────────────
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)

# ── Feature window builder ────────────────────────────────────────
# 60-second windows per entity
builder = FeatureWindowBuilder(window_seconds=60)

print('[forwarder] Starting. Listening on stdin for Falco JSON...',
      flush=True)

# Verify Redis is reachable before entering main loop
try:
    r.ping()
    print('[forwarder] Redis connection: OK', flush=True)
except redis.RedisError as e:
    print(f'[forwarder] FATAL: Redis not reachable: {e}', flush=True)
    sys.exit(1)

# ── Main loop ────────────────────────────────────────────────────
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    # ── Parse Falco JSON ─────────────────────────────────────────
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        # Falco sometimes emits startup messages that are not JSON
        continue

    # ── Extract fields ───────────────────────────────────────────
    fields = event.get('output_fields', {})
    rule   = event.get('rule', '')

    raw = {
        'rule':      rule,
        'priority':  event.get('priority', 'DEBUG'),
        'proc_name': fields.get('proc.name',  ''),
        'proc_pid':  fields.get('proc.pid',    0),
        'proc_ppid': fields.get('proc.ppid',   0),
        'user_name': fields.get('user.name',  ''),
        'fd_sip':    fields.get('fd.sip',     ''),
        'fd_sport':  fields.get('fd.sport',   ''),
        'fd_name':   fields.get('fd.name',    ''),
        'evt_type':  fields.get('evt.type',   ''),
        'hostname':  fields.get('hostname',   ''),
        'timestamp': time.time(),
    }

    # ── Push raw event to Redis debug log ───────────────────────
    try:
        r.lpush('falco_raw_events', json.dumps(raw))
        r.ltrim('falco_raw_events', 0, 999)  # keep last 1000
    except redis.RedisError as e:
        print(f'[forwarder] Redis write error (raw): {e}', flush=True)
        continue

    # ── Feed into sliding window aggregator ─────────────────────
    try:
        ready_vectors = builder.ingest(raw)
    except Exception as e:
        print(f'[forwarder] Feature builder error: {e}', flush=True)
        continue

    # ── Push completed feature vectors to ML pipeline ───────────
    for vec in ready_vectors:
        try:
            r.lpush(FALCO_EVENTS_QUEUE, json.dumps(vec))
            r.ltrim(FALCO_EVENTS_QUEUE, 0, 499)
            eid = vec.get('entity_id', '?')
            ro  = vec['host_features'].get('rule_outbound', 0)
            rp  = vec['host_features'].get('rule_priv_esc', 0)
            rs  = vec['host_features'].get('rule_sensitive_file', 0)
            print(
                f'[forwarder] Vector pushed: entity={eid}'
                f' outbound={ro} priv_esc={rp} sensitive={rs}',
                flush=True
            )
        except redis.RedisError as e:
            print(f'[forwarder] Redis write error (vector): {e}', flush=True)

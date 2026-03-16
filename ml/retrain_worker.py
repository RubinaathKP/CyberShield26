"""
Retraining worker — polls honeypot_retrain_queue in Redis and updates
the meta-classifier via partial_fit every RETRAIN_EVERY confirmed events.

Run alongside the API server:
    python ml/retrain_worker.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis
import json
import time
import numpy as np
from ml.model_store import ModelStore

import collections

# ── Redis with in-memory fallback ─────────────────────────────────────
class InMemoryRedis:
    def __init__(self):
        self._lists = collections.defaultdict(collections.deque)
        self._hashes = collections.defaultdict(dict)
        self._sets = collections.defaultdict(set)
        self._strings = {}

    def lpush(self, key, *values):
        for v in values: self._lists[key].appendleft(v)
        return len(self._lists[key])

    def rpop(self, key):
        try: return self._lists[key].pop()
        except IndexError: return None

    def hgetall(self, key):
        return self._hashes.get(key, {})

    def ping(self): return True

def _get_redis():
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return r
    except Exception:
        return InMemoryRedis()

r     = _get_redis()
store = ModelStore.get()

RETRAIN_EVERY  = 10   # retrain after every N honeypot confirmations
SLEEP_INTERVAL = 5    # seconds between queue polls

buffer_X = []
buffer_y = []

print('Retraining worker started. Polling honeypot_retrain_queue...')

while True:
    try:
        raw = r.rpop('honeypot_retrain_queue')
        if raw:
            event = json.loads(raw)
            label = event.get('label', 1)

            # Pull p_host / p_network from Redis entity scores if available
            entity_key = f"entity_scores:{event.get('src_ip', 'unknown')}"
            scores_raw = r.hgetall(entity_key)

            if scores_raw and 'p_host' in scores_raw and 'p_network' in scores_raw:
                p_host = float(scores_raw['p_host'])
                p_net  = float(scores_raw['p_network'])
            else:
                # Fallback: use high-confidence synthetic values for confirmed events
                p_host = 0.90
                p_net  = 0.85

            buffer_X.append([p_host, p_net])
            buffer_y.append(label)

            if len(buffer_X) >= RETRAIN_EVERY:
                X_new = np.array(buffer_X)
                y_new = np.array(buffer_y)
                store.retrain_meta(X_new, y_new)
                print(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] Retrained on '
                      f'{len(buffer_X)} honeypot samples.')
                buffer_X.clear()
                buffer_y.clear()

    except redis.exceptions.ConnectionError as e:
        print(f'Redis connection error: {e}. Retrying in {SLEEP_INTERVAL}s...')
    except Exception as e:
        print(f'Unexpected error: {e}')

    time.sleep(SLEEP_INTERVAL)

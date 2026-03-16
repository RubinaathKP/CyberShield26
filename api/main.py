import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import json
import time
import numpy as np
import collections

from ml.model_store import ModelStore
from ml.explain import ThreatExplainer
from fastapi.staticfiles import StaticFiles

app = FastAPI(title='Threat Detection API', version='1.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

# ── Static Files (Scenarios) ──────────────────────────────────────────
# Mount the root scenarios folder to /scenarios
app.mount("/scenarios", StaticFiles(directory="scenarios"), name="scenarios")

# ── Redis with in-memory fallback ─────────────────────────────────────
class InMemoryRedis:
    """Minimal Redis-compatible in-memory store for running without Redis."""

    def __init__(self):
        self._lists: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._hashes: dict[str, dict] = collections.defaultdict(dict)
        self._sets: dict[str, set] = collections.defaultdict(set)
        self._strings: dict[str, str] = {}

    def lpush(self, key, *values):
        for v in values:
            self._lists[key].appendleft(v)
        return len(self._lists[key])

    def lrange(self, key, start, stop):
        lst = list(self._lists.get(key, []))
        if stop == -1:
            return lst[start:]
        return lst[start:stop + 1]

    def ltrim(self, key, start, stop):
        lst = list(self._lists.get(key, []))
        self._lists[key] = collections.deque(lst[start:stop + 1])

    def llen(self, key):
        return len(self._lists.get(key, []))

    def hset(self, key, mapping=None, **kwargs):
        if mapping:
            self._hashes[key].update(mapping)
        self._hashes[key].update(kwargs)

    def expire(self, key, ttl):
        pass  # TTL not enforced in memory

    def sadd(self, key, *members):
        self._sets[key].update(members)
        return len(members)

    def scard(self, key):
        return len(self._sets.get(key, set()))

    def get(self, key):
        return self._strings.get(key)

    def set(self, key, value):
        self._strings[key] = str(value)

    def incr(self, key):
        val = int(self._strings.get(key, 0)) + 1
        self._strings[key] = str(val)
        return val

    def ping(self):
        return True


def _get_redis():
    """Try Redis first; fall back to in-memory implementation."""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, decode_responses=True, socket_connect_timeout=1)
        r.ping()
        print("[INFO] Connected to Redis server.")
        return r
    except Exception:
        print("[WARN] Redis not available - using in-memory store (data will not persist across restarts).")
        return InMemoryRedis()


r = _get_redis()


# ── Request / Response Schemas ────────────────────────────────────────
class PredictRequest(BaseModel):
    host_features: dict
    net_features:  dict
    entity_id:     str       # IP or PID for correlation


class FeedbackRequest(BaseModel):
    entity_id: str
    p_host:    float
    p_net:     float
    label:     int           # 0 = benign, 1 = malicious


# ── Startup ───────────────────────────────────────────────────────────
@app.on_event('startup')
async def startup():
    store = ModelStore.get()
    app.state.explainer = ThreatExplainer(
        store.host_rf, store.net_rf,
        store.host_cols, store.net_cols,
    )


# ── Health Check ──────────────────────────────────────────────────────
@app.get('/')
async def health():
    return {'status': 'ok', 'service': 'Threat Detection API', 'version': '1.0'}


# ── Predict Endpoint ──────────────────────────────────────────────────
@app.post('/predict')
async def predict(payload: dict):
    detected_at = time.time()
    store  = ModelStore.get()

    host_features = payload.get('host_features', {})
    net_features  = payload.get('net_features', {})

    try:
        result = store.predict(host_features, net_features)

        # Attach SHAP explanations
        x_host_sc = store.host_scaler.transform(
            np.array([[host_features[c] for c in store.host_cols]])
        )[0]
        x_net_sc = store.net_scaler.transform(
            np.array([[net_features.get(c, 0) for c in store.net_cols]]) if net_features else np.zeros((1, len(store.net_cols)))
        )[0]

        result['shap_host']    = app.state.explainer.explain_host(x_host_sc)[:5]
        result['shap_network'] = app.state.explainer.explain_network(x_net_sc)[:5]
        result['shap_meta']    = app.state.explainer.explain_meta(
            result['p_host'], result['p_network']
        )
    except Exception:
        result = {
            'p_host': 0.0,
            'p_network': 0.0,
            'final_score': 0.0,
            'threat_level': 'LOW'
        }

    # Calculate MTTD if event_timestamp is available
    event_ts = payload.get('window_end') or payload.get('event_timestamp')
    mttd_seconds = None
    if event_ts:
        mttd_seconds = round(detected_at - float(event_ts), 3)

    # Build alert object
    alert = {
        'id':           str(int(detected_at * 1000)),
        'entity_id':    payload.get('entity_id', 'unknown'),
        'p_host':       result.get('p_host', 0.0),
        'p_network':    result.get('p_network', 0.0),
        'final_score':  result.get('final_score', 0.0),
        'threat_level': result.get('threat_level', 'LOW'),
        'timestamp':    detected_at,  # Changed from detected_at to timestamp for dashboard consistency
        'mttd_seconds': mttd_seconds,
        'shap_host':    result.get('shap_host', []),
        'shap_network': result.get('shap_network', []),
        'shap_meta':    result.get('shap_meta', []),
    }

    if alert['final_score'] > 0.85:
        entity_key = f"entity_scores:{alert['entity_id']}"
        r.hset(entity_key, mapping={
            'p_host':    alert['p_host'],
            'p_network': alert['p_network'],
            'score':     alert['final_score'],
        })
        r.expire(entity_key, 86400)   # TTL: 24 hours
        r.sadd('honeypot_ips', alert['entity_id'])

    # Store alert in Redis
    r.lpush('alerts', json.dumps(alert))
    r.ltrim('alerts', 0, 499)

    # Track MTTD for metrics
    if mttd_seconds is not None:
        r.lpush('mttd_samples', mttd_seconds)
        r.ltrim('mttd_samples', 0, 99)   # keep last 100 samples

    return alert


# ── Alert History ─────────────────────────────────────────────────────
@app.get('/alerts/history')
async def alert_history(limit: int = 50):
    raw = r.lrange('alerts', 0, limit - 1)
    return [json.loads(a) for a in raw]


# ── Metrics Endpoint ──────────────────────────────────────────────────
@app.get('/metrics')
async def get_metrics():
    total_alerts      = r.llen('alerts')
    honeypot_events   = r.llen('honeypot_events')
    honeypot_ip_count = r.scard('honeypot_ips')
    retrain_events    = int(r.get('retrain_count') or 0)

    # Calculate average MTTD from samples
    mttd_samples = r.lrange('mttd_samples', 0, -1)
    avg_mttd = None
    if mttd_samples:
        vals = [float(v) for v in mttd_samples]
        avg_mttd = round(sum(vals) / len(vals), 3)

    # Threat distribution counts
    alerts_raw = r.lrange('alerts', 0, 49)
    threat_counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
    for a in alerts_raw:
        try:
            level = json.loads(a).get('threat_level','LOW')
            if level in threat_counts:
                threat_counts[level] += 1
        except:
            pass

    # Build timeline: bucket alerts by hour for the last 24h
    # Build timeline: bucket alerts by 5-minute intervals for the last 60 minutes
    now = time.time()
    timeline = {}
    for i in range(12, -1, -1):
        # 5-minute buckets
        ts_bucket = (int(now / 300) - i) * 300
        label = time.strftime("%H:%M", time.localtime(ts_bucket))
        timeline[label] = 0
    
    # Attack vectors count from honeypot events
    attack_vectors = collections.defaultdict(int)
    h_raw = r.lrange('honeypot_events', 0, 499)
    for h in h_raw:
        try:
            evt = json.loads(h)
            etype = evt.get('event_type', 'unknown')
            attack_vectors[etype] += 1
        except: pass

    # Fill timeline from actual alerts
    for a in alerts_raw:
        try:
            alert = json.loads(a)
            ts = alert.get('timestamp', now)
            # Find the 5-minute bucket for this alert
            bucket_ts = int(ts / 300) * 300
            label = time.strftime("%H:%M", time.localtime(bucket_ts))
            if label in timeline:
                timeline[label] += 1
        except: pass

    # Convert timeline to sorted list of objects (maintaining chronological order)
    sorted_timeline = []
    # Using the keys from our initialization to ensure order
    for lb in sorted(timeline.keys(), key=lambda x: x):
        sorted_timeline.append({"time": lb, "alerts": timeline[lb]})

    # Convert attack vectors to list
    vector_list = []
    colors = ['#ff6b6b', '#ff9f43', '#feca57', '#7b61ff', '#48dbfb', '#1dd1a1']
    for i, (name, count) in enumerate(attack_vectors.items()):
        vector_list.append({"name": name, "count": count, "fill": colors[i % len(colors)]})
    
    # If empty, add some 0s so chart doesn't break
    if not vector_list:
        vector_list = [{"name": "No Data", "count": 0, "fill": "#ccc"}]

    return {
        'total_alerts':      total_alerts,
        'honeypot_events':   honeypot_events,
        'honeypot_ip_count': honeypot_ip_count,
        'retrain_events':    retrain_events,
        'avg_mttd_seconds':  avg_mttd,
        'threat_counts':     threat_counts,
        'timeline':          sorted_timeline,
        'attack_vectors':    vector_list
    }



# ── Feedback / Retraining Endpoint ───────────────────────────────────
@app.post('/feedback')
async def feedback(req: FeedbackRequest):
    import numpy as np
    ModelStore.get().retrain_meta(
        np.array([[req.p_host, req.p_net]]),
        np.array([req.label]),
    )
    return {'status': 'retrained', 'entity_id': req.entity_id}


# ── Honeypot Log Endpoint ─────────────────────────────────────────────
@app.get('/honeypot/log')
async def honeypot_log(limit: int = 50):
    raw = r.lrange('honeypot_events', 0, limit - 1)
    return [json.loads(e) for e in raw]

@app.get('/honeypot/ips')
async def honeypot_ips():
    ips = list(r.smembers('honeypot_ips') if hasattr(r, 'smembers') else r._sets.get('honeypot_ips', set()))
    return {"flagged_ips": ips}

@app.get('/alerts/{alert_id}/explain')
async def explain_alert(alert_id: str):
    # Search for alert in recent history
    raw = r.lrange('alerts', 0, 499)
    for a in raw:
        alert = json.loads(a)
        if alert.get('id') == alert_id:
            return alert
    return {"error": "Alert not found or explanations expired"}

class AnalyzeRequest(BaseModel):
    payload: str

@app.post('/demo/analyze')
async def analyze_payload(req: AnalyzeRequest):
    # Mock payload analyzer for dashboard demo
    is_malicious = any(x in req.payload.lower() for x in ['select', 'union', 'exec', 'bash', '../', 'etc/passwd'])
    score = 0.95 if is_malicious else 0.02
    
    findings = []
    if "select" in req.payload.lower() or "union" in req.payload.lower():
        findings.append("SQL Injection Pattern")
    if "../" in req.payload.lower() or "etc/passwd" in req.payload.lower():
        findings.append("Path Traversal")
    if "bash" in req.payload.lower() or "exec" in req.payload.lower():
        findings.append("Shell Execution")
        
    return {
        "is_threat": is_malicious,
        "confidence": score,
        "threat_type": findings[0] if findings else ("Pattern Match" if is_malicious else "None"),
        "explanation": f"Detected {len(findings)} suspicious patterns in the provided byte stream." if findings else "No immediate threat patterns identified in the payload.",
        "seriousness_score": round(score * 10, 1)
    }


# ── WebSocket Live Alert Stream ───────────────────────────────────────
@app.websocket('/alerts/live')
async def alert_stream(ws: WebSocket):
    await ws.accept()
    last_ts = 0.0
    try:
        while True:
            raw = r.lrange('alerts', 0, 0)
            if raw:
                alert = json.loads(raw[0])
                ts = alert.get('timestamp', 0)
                if ts > last_ts:
                    last_ts = ts
                    await ws.send_text(json.dumps(alert))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass

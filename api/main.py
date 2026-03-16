import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import json
import redis
import time
import numpy as np

from ml.model_store import ModelStore
from ml.explain import ThreatExplainer

app = FastAPI(title='Threat Detection API', version='1.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

r = redis.Redis(host='localhost', port=6379, decode_responses=True)


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
        'detected_at':  detected_at,
        'mttd_seconds': mttd_seconds,
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

    return {
        'total_alerts':      total_alerts,
        'honeypot_events':   honeypot_events,
        'honeypot_ip_count': honeypot_ip_count,
        'retrain_events':    retrain_events,
        'avg_mttd_seconds':  avg_mttd,
        'threat_counts':     threat_counts,
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

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
async def predict(req: PredictRequest):
    store  = ModelStore.get()
    result = store.predict(req.host_features, req.net_features)

    # Attach SHAP explanations
    x_host_sc = store.host_scaler.transform(
        np.array([[req.host_features[c] for c in store.host_cols]])
    )[0]
    x_net_sc = store.net_scaler.transform(
        np.array([[req.net_features[c] for c in store.net_cols]])
    )[0]

    result['shap_host']    = app.state.explainer.explain_host(x_host_sc)[:5]
    result['shap_network'] = app.state.explainer.explain_network(x_net_sc)[:5]
    result['shap_meta']    = app.state.explainer.explain_meta(
        result['p_host'], result['p_network']
    )
    result['entity_id'] = req.entity_id
    result['timestamp'] = time.time()

    # Push to Redis alert stream for dashboard
    r.lpush('alerts', json.dumps(result))
    r.ltrim('alerts', 0, 999)   # Keep last 1000 alerts

    # Honeypot trigger: store scores and flag IP
    if result['final_score'] > 0.85:
        entity_key = f"entity_scores:{req.entity_id}"
        r.hset(entity_key, mapping={
            'p_host':    result['p_host'],
            'p_network': result['p_network'],
            'score':     result['final_score'],
        })
        r.expire(entity_key, 86400)   # TTL: 24 hours
        r.sadd('honeypot_ips', req.entity_id)

    return result


# ── Alert History ─────────────────────────────────────────────────────
@app.get('/alerts/history')
async def alert_history(limit: int = 50):
    raw = r.lrange('alerts', 0, limit - 1)
    return [json.loads(a) for a in raw]


# ── Metrics Endpoint ──────────────────────────────────────────────────
@app.get('/metrics')
async def metrics():
    return {
        'honeypot_ip_count':  r.scard('honeypot_ips'),
        'total_alerts':       r.llen('alerts'),
        'honeypot_events':    r.llen('honeypot_events'),
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

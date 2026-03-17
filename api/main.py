import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, cast, Dict, Any, List
import asyncio
import json
import redis
import time
import logging
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

app.mount("/scenarios", StaticFiles(directory="scenarios"), name="scenarios")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.middleware("http")
async def log_requests(request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

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

@app.get('/dashboard/health')
async def dashboard_health():
    try:
        r.ping()
        redis_status = 'connected'
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        redis_status = 'disconnected'
    
    return {
        'status': 'operational' if redis_status == 'connected' else 'degraded',
        'db': 'connected', 
        'redis': redis_status
    }


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
            np.array([[host_features.get(c, 0.0) for c in store.host_cols]])
        )[0]
        x_net_sc = store.net_scaler.transform(
            np.array([[net_features.get(c, 0.0) for c in store.net_cols]])
        )[0]

        result['shap_host']    = app.state.explainer.explain_host(x_host_sc)[:5]
        result['shap_network'] = app.state.explainer.explain_network(x_net_sc)[:5]
        result['shap_meta']    = app.state.explainer.explain_meta(
            result['p_host'], result['p_net']
        )
    except Exception as e:
        logger.error(f"Prediction or explanation failed: {e}")
        result = {
            'p_host': 0.0,
            'p_net': 0.0,
            'final_score': 0.0,
            'threat_level': 'LOW',
            'error': str(e)
        }

    # Calculate MTTD if event_timestamp is available
    event_ts = payload.get('window_end') or payload.get('event_timestamp')
    mttd_seconds = None
    if event_ts:
        mttd_seconds = round(float(detected_at) - float(event_ts), 3)

    # Build alert object
    alert = {
        'id':           str(int(detected_at * 1000)),
        'entity_id':    payload.get('entity_id', 'unknown'),
        'p_host':       result.get('p_host', 0.0),
        'p_net':        result.get('p_net', 0.0),
        'final_score':  result.get('final_score', 0.0),
        'threat_level': result.get('threat_level', 'LOW'),
        'detected_at':  detected_at,
        'timestamp':    detected_at,  # Synchronized with WebSocket
        'mttd_seconds': mttd_seconds,
        'shap_host':    result.get('shap_host', []),
        'shap_network': result.get('shap_network', []),
        'shap_meta':    result.get('shap_meta', []),
    }
    score_val = alert.get('final_score', 0.0)
    if float(score_val if score_val is not None else 0.0) > 0.85:
        entity_key = f"entity_scores:{alert['entity_id']}"
        r.hset(entity_key, mapping={
            'p_host':    alert['p_host'],
            'p_net':     alert['p_net'],
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
        avg_mttd = round(float(sum(vals)) / len(vals), 3)

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
async def feedback(req: dict):
    # Map frontend request to retrain logic
    # Frontend sends { alert_id, accurate, comments }
    # Backend needs entity_id, p_host, p_net, label
    alert_raw = r.lrange('alerts', 0, -1)
    target_alert = None
    for a in alert_raw:
        parsed = json.loads(a)
        if parsed.get('id') == str(req.get('alert_id')):
            target_alert = parsed
            break
    
    if target_alert:
        target_alert = cast(Dict[str, Any], target_alert)
        score_val = target_alert.get('final_score', 0.0)
        label = 1 if float(score_val if score_val is not None else 0.0) > 0.5 else 0
        if not req.get('accurate'):
            label = 1 - label # flip it if user says it's inaccurate
            
        ModelStore.get().retrain_meta(
            np.array([[float(target_alert.get('p_host') or 0.0), float(target_alert.get('p_net') or 0.0)]]),
            np.array([label]),
        )
    return {'status': 'processed'}

# ── Alert Explanation Endpoint ──────────────────────────────────────
@app.get('/alerts/{id}/explain')
async def explain_alert(id: str):
    alert_raw = r.lrange('alerts', 0, -1)
    for a in alert_raw:
        parsed = json.loads(a)
        if parsed.get('id') == id:
            # Reconstruct prediction result for explanation
            # (Note: In a real app we'd store the features too)
            return {
                'id': id,
                'summary': f"Threat level {parsed['threat_level']} detected for {parsed['entity_id']}",
                'impact': 'High' if parsed['final_score'] > 0.8 else 'Medium',
                'recommendation': 'Isolate host' if parsed['final_score'] > 0.8 else 'Monitor closely'
            }
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail='Alert not found')

# ── Demo Analysis Endpoint ──────────────────────────────────────────
@app.post('/demo/analyze')
async def analyze_payload(req: dict):
    # Dummy analysis for demo purposes
    payload = req.get('payload', '')
    score = 0.1
    if 'eval(' in payload or 'system(' in payload:
        score = 0.95
    return {
        'score': score,
        'threat_level': 'CRITICAL' if score > 0.8 else 'LOW',
        'findings': ['Potential RCE payload'] if score > 0.8 else []
    }


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

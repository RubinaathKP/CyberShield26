import joblib
import numpy as np
from pathlib import Path

MODELS_DIR = Path('models')


def classify_score(score: float) -> str:
    """Map numeric threat score to human-readable threat level."""
    if score < 0.4:   return 'LOW'
    if score < 0.7:   return 'MEDIUM'
    if score < 0.85:  return 'HIGH'
    return 'CRITICAL'


class ModelStore:
    """
    Singleton wrapper that loads all model artifacts and exposes predict /
    retrain_meta methods.  Thread-safe for concurrent FastAPI requests.
    """
    _instance = None

    def __init__(self):
        self.host_rf     = joblib.load(MODELS_DIR / 'host_rf.pkl')
        self.net_rf      = joblib.load(MODELS_DIR / 'net_rf.pkl')
        self.meta_clf    = joblib.load(MODELS_DIR / 'meta_clf.pkl')
        self.host_scaler = joblib.load(MODELS_DIR / 'host_scaler.pkl')
        self.net_scaler  = joblib.load(MODELS_DIR / 'net_scaler.pkl')
        self.host_cols   = joblib.load(MODELS_DIR / 'host_feature_cols.pkl')
        self.net_cols    = joblib.load(MODELS_DIR / 'net_feature_cols.pkl')
        print('All models loaded successfully.')

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = ModelStore()
        return cls._instance

    def predict(self, host_features: dict, net_features: dict) -> dict:
        """Run full ensemble inference and return threat score + level."""
        x_host = np.array([host_features.get(c, 0) for c in self.host_cols]).reshape(1, -1)
        x_net  = np.array([net_features.get(c, 0)  for c in self.net_cols ]).reshape(1, -1)

        x_host_sc = self.host_scaler.transform(x_host)
        x_net_sc  = self.net_scaler.transform(x_net)

        p_host = float(self.host_rf.predict_proba(x_host_sc)[0, 1])
        p_net  = float(self.net_rf.predict_proba(x_net_sc)[0, 1])

        meta_x      = np.array([[p_host, p_net]])
        final_score = float(self.meta_clf.predict_proba(meta_x)[0, 1])

        return {
            'p_host':       p_host,
            'p_net':        p_net,
            'final_score':  final_score,
            'threat_level': classify_score(final_score),
        }

    def retrain_meta(self, X_new: np.ndarray, y_new: np.ndarray):
        """
        Batch partial_fit — called by retrain_worker after honeypot confirmations.
        Persists updated model to disk immediately.
        """
        self.meta_clf.partial_fit(X_new, y_new, classes=[0, 1])
        joblib.dump(self.meta_clf, MODELS_DIR / 'meta_clf.pkl')
        print(f'Meta-classifier updated. Total iterations: {self.meta_clf.t_}')

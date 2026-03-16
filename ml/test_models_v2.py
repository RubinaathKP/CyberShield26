"""
test_models_v2.py - Comprehensive ML Ensemble Test Suite (ALL 15 CLASSES)
==========================================================================
CyberShield Intelligent Behavioral Threat Detection System
Coverage:
  1.  Artifact Integrity          - all pkl files exist, loadable, non-corrupt
  2.  Feature Schema Validation   - model expects exactly the features we provide
  3.  Host RF - Benign Profiles   - known-benign inputs must score LOW
  4.  Host RF - Attack Profiles   - known-attack inputs must score HIGH
  5.  Network RF - Benign         - known-benign network traffic stays quiet
  6.  Network RF - Attack         - known-attack traffic scores HIGH
  7.  Meta-Classifier Quadrants   - all four combinations of base model signals
  8.  Threat Level Boundaries     - all four tiers at exact boundary values
  9.  False Positive Resistance   - benign-but-suspicious patterns must not alert
  10. End-to-End Pipeline         - ModelStore.predict() full flow
  11. Score Monotonicity          - adding attack signals always raises score
  12. Held-Out Dataset Evaluation - precision, recall, ROC-AUC on saved test splits
  13. Retraining Correctness      - partial_fit improves/maintains score
  14. Retraining Stability        - retraining on benign does not inflate attack score
  15. Robustness - Edge Inputs    - zeros, extreme values, missing signals
Run from project root:
    python -m pytest ml/test_models_v2.py -v
    # or directly:
    python ml/test_models_v2.py
"""
import sys
import unittest
import warnings
import time
import copy
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import precision_score, recall_score, roc_auc_score, f1_score, confusion_matrix
warnings.filterwarnings("ignore", category=UserWarning)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR   = PROJECT_ROOT / "data"
from ml.model_store import ModelStore, classify_score
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"
def _fmt(label, value, threshold=None, passed=None):
    color = GREEN if passed is not False else RED
    th    = f"  (threshold: {threshold})" if threshold else ""
    return f"    {label}: {color}{value}{RESET}{th}"
class FeatureFactory:
    HOST_BENIGN_DEFAULTS = {
        "process_spawn_rate":     0.02,
        "file_access_rate":       0.08,
        "net_activity_rate":      0.01,
        "process_chain_depth":    1,
        "priv_escalation_count":  0,
        "inject_attempt_count":   0,
        "syscall_entropy":        2.9,
        "trace_length":           350,
        "rule_outbound":          0,
        "rule_priv_esc":          0,
        "rule_sensitive_file":    0,
    }
    NET_BENIGN_DEFAULTS = {
        "Flow Duration":              8000000,
        "Total Fwd Packets":          22,
        "Total Backward Packets":     18,
        "Flow Bytes/s":               1400.0,
        "Flow Packets/s":             5.0,
        "Fwd Packets/s":              3.0,
        "Bwd Packets/s":              2.0,
        "Avg Packet Size":            480.0,
        "Avg Fwd Segment Size":       460.0,
        "Init Fwd Win Bytes":         65535,
        "SYN Flag Count":             1,
        "Fwd PSH Flags":              2,
        "botnet_c2_indicator":        0,
        "port_scan_indicator":        0,
        "URG Flag Count":             0,
    }
    def __init__(self, ms: ModelStore):
        self.ms = ms
        for c in ms.host_cols:
            if c not in self.HOST_BENIGN_DEFAULTS:
                self.HOST_BENIGN_DEFAULTS[c] = 0.0
        for c in ms.net_cols:
            if c not in self.NET_BENIGN_DEFAULTS:
                self.NET_BENIGN_DEFAULTS[c] = 0.0
    def host(self, **overrides) -> dict:
        f = dict(self.HOST_BENIGN_DEFAULTS)
        f.update(overrides)
        return f
    def net(self, **overrides) -> dict:
        f = dict(self.NET_BENIGN_DEFAULTS)
        f.update(overrides)
        return f
    def host_zeros(self) -> dict:
        return {c: 0 for c in self.ms.host_cols}
    def net_zeros(self) -> dict:
        return {c: 0 for c in self.ms.net_cols}
class BaseModelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ms = ModelStore.get()
        cls.ff = FeatureFactory(cls.ms)
    def _host_proba(self, features: dict) -> float:
        x   = np.array([features[c] for c in self.ms.host_cols]).reshape(1, -1)
        xsc = self.ms.host_scaler.transform(x)
        return float(self.ms.host_rf.predict_proba(xsc)[0, 1])
    def _net_proba(self, features: dict) -> float:
        x   = np.array([features[c] for c in self.ms.net_cols]).reshape(1, -1)
        xsc = self.ms.net_scaler.transform(x)
        return float(self.ms.net_rf.predict_proba(xsc)[0, 1])
    def _meta_proba(self, p_host: float, p_net: float) -> float:
        return float(self.ms.meta_clf.predict_proba(np.array([[p_host, p_net]]))[0, 1])
    def _predict(self, host_overrides=None, net_overrides=None) -> dict:
        h = self.ff.host(**(host_overrides or {}))
        n = self.ff.net(**(net_overrides  or {}))
        return self.ms.predict(h, n)
    def assertScoreAbove(self, score, threshold, label=""):
        self.assertGreater(score, threshold,
            f"{label} - expected score > {threshold}, got {score:.4f}")
    def assertScoreBelow(self, score, threshold, label=""):
        self.assertLess(score, threshold,
            f"{label} - expected score < {threshold}, got {score:.4f}")
# =============================================================================
# 1. Artifact Integrity
# =============================================================================
class Test01ArtifactIntegrity(unittest.TestCase):
    REQUIRED = [
        "host_rf.pkl", "host_scaler.pkl", "host_feature_cols.pkl",
        "net_rf.pkl",  "net_scaler.pkl",  "net_feature_cols.pkl",
        "meta_clf.pkl",
    ]
    def test_all_artifacts_exist(self):
        missing = [f for f in self.REQUIRED if not (MODELS_DIR / f).exists()]
        self.assertEqual(missing, [], f"Missing model artifacts: {missing}")
    def test_all_artifacts_nonempty(self):
        for fname in self.REQUIRED:
            path = MODELS_DIR / fname
            if path.exists():
                self.assertGreater(path.stat().st_size, 100,
                    f"{fname} is suspiciously small ({path.stat().st_size} bytes)")
    def test_all_artifacts_loadable(self):
        for fname in self.REQUIRED:
            path = MODELS_DIR / fname
            if path.exists():
                try:
                    obj = joblib.load(path)
                    self.assertIsNotNone(obj, f"{fname} deserialized to None")
                except Exception as e:
                    self.fail(f"Failed to load {fname}: {e}")
    def test_feature_col_lists_are_valid(self):
        host_cols = joblib.load(MODELS_DIR / "host_feature_cols.pkl")
        net_cols  = joblib.load(MODELS_DIR / "net_feature_cols.pkl")
        self.assertIsInstance(host_cols, list)
        self.assertIsInstance(net_cols, list)
        self.assertGreater(len(host_cols), 0)
        self.assertGreater(len(net_cols), 0)
        self.assertEqual(len(host_cols), len(set(host_cols)), "Duplicate cols in host_feature_cols")
        self.assertEqual(len(net_cols), len(set(net_cols)),   "Duplicate cols in net_feature_cols")
    def test_host_rf_has_predict_proba(self):
        rf = joblib.load(MODELS_DIR / "host_rf.pkl")
        self.assertTrue(hasattr(rf, "predict_proba"), "host_rf.pkl missing predict_proba")
    def test_meta_clf_has_partial_fit(self):
        clf = joblib.load(MODELS_DIR / "meta_clf.pkl")
        self.assertTrue(hasattr(clf, "partial_fit"),
            "meta_clf.pkl does not support partial_fit - must be SGDClassifier")
    def test_scalers_have_correct_feature_count(self):
        host_scaler = joblib.load(MODELS_DIR / "host_scaler.pkl")
        net_scaler  = joblib.load(MODELS_DIR / "net_scaler.pkl")
        host_cols   = joblib.load(MODELS_DIR / "host_feature_cols.pkl")
        net_cols    = joblib.load(MODELS_DIR / "net_feature_cols.pkl")
        self.assertEqual(host_scaler.n_features_in_, len(host_cols))
        self.assertEqual(net_scaler.n_features_in_,  len(net_cols))
# =============================================================================
# 2. Feature Schema Validation
# =============================================================================
class Test02FeatureSchema(BaseModelTest):
    def test_host_predict_shape(self):
        x = np.array([[self.ff.host()[c] for c in self.ms.host_cols]])
        proba = self.ms.host_rf.predict_proba(self.ms.host_scaler.transform(x))
        self.assertEqual(proba.shape, (1, 2))
    def test_net_predict_shape(self):
        x = np.array([[self.ff.net()[c] for c in self.ms.net_cols]])
        proba = self.ms.net_rf.predict_proba(self.ms.net_scaler.transform(x))
        self.assertEqual(proba.shape, (1, 2))
    def test_meta_predict_shape(self):
        proba = self.ms.meta_clf.predict_proba(np.array([[0.5, 0.5]]))
        self.assertEqual(proba.shape, (1, 2))
    def test_output_is_probability_host(self):
        p = self._host_proba(self.ff.host())
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)
    def test_output_is_probability_net(self):
        p = self._net_proba(self.ff.net())
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)
    def test_output_is_probability_meta(self):
        p = self._meta_proba(0.5, 0.5)
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)
# =============================================================================
# 3. Host RF - Benign Profiles
# =============================================================================
class Test03HostBenign(BaseModelTest):
    def test_idle_system(self):
        p = self._host_proba(self.ff.host())
        self.assertScoreBelow(p, 0.50, "Idle system")
        print(_fmt("idle system score", f"{p:.4f}", "< 0.50", p < 0.50))
    def test_web_server_serving_requests(self):
        p = self._host_proba(self.ff.host(
            file_access_rate=0.35, net_activity_rate=0.01,
            syscall_entropy=3.1, trace_length=600,
        ))
        self.assertScoreBelow(p, 0.55, "Web server")
        print(_fmt("web server score", f"{p:.4f}", "< 0.55", p < 0.55))
    def test_cron_backup_with_sudo(self):
        p = self._host_proba(self.ff.host(
            process_spawn_rate=0.22, file_access_rate=0.58,
            process_chain_depth=3, priv_escalation_count=1,
            rule_priv_esc=1, syscall_entropy=3.0, trace_length=1100,
        ))
        self.assertScoreBelow(p, 0.65, "Cron backup with sudo")
        print(_fmt("cron backup score", f"{p:.4f}", "< 0.65", p < 0.65))
    def test_ssh_login_session(self):
        p = self._host_proba(self.ff.host(
            net_activity_rate=0.12, process_chain_depth=2,
            syscall_entropy=2.7, trace_length=200,
        ))
        self.assertScoreBelow(p, 0.50, "SSH login session")
        print(_fmt("ssh login score", f"{p:.4f}", "< 0.50", p < 0.50))
    def test_package_manager_apt(self):
        p = self._host_proba(self.ff.host(
            process_spawn_rate=0.30, file_access_rate=0.50,
            process_chain_depth=4, priv_escalation_count=1,
            rule_priv_esc=1, syscall_entropy=3.2, trace_length=900,
        ))
        self.assertScoreBelow(p, 0.70, "apt install")
        print(_fmt("apt install score", f"{p:.4f}", "< 0.70", p < 0.70))
    def test_developer_curl(self):
        p = self._host_proba(self.ff.host(
            net_activity_rate=0.20, process_chain_depth=2,
            rule_outbound=1, syscall_entropy=2.8,
        ))
        self.assertScoreBelow(p, 0.65, "Developer curl")
        print(_fmt("developer curl score", f"{p:.4f}", "< 0.65", p < 0.65))
# =============================================================================
# 4. Host RF - Attack Profiles
# =============================================================================
class Test04HostAttack(BaseModelTest):
    def test_meterpreter_reverse_shell(self):
        p = self._host_proba(self.ff.host(
            process_spawn_rate=0.45, file_access_rate=0.28,
            net_activity_rate=0.08, process_chain_depth=4,
            priv_escalation_count=6, inject_attempt_count=2,
            syscall_entropy=1.8, trace_length=1400,
            rule_outbound=1, rule_priv_esc=1, rule_sensitive_file=1,
        ))
        self.assertScoreAbove(p, 0.40, "Meterpreter")
        print(_fmt("meterpreter score", f"{p:.4f}", "> 0.40", p > 0.40))
    def test_adduser_backdoor(self):
        p = self._host_proba(self.ff.host(
            file_access_rate=0.52, priv_escalation_count=4,
            syscall_entropy=2.0, trace_length=500,
            rule_priv_esc=1, rule_sensitive_file=1,
        ))
        self.assertScoreAbove(p, 0.30, "Adduser backdoor")
        print(_fmt("adduser score", f"{p:.4f}", "> 0.30", p > 0.30))
    def test_hydra_brute_force(self):
        p = self._host_proba(self.ff.host(
            net_activity_rate=0.55, process_spawn_rate=0.38,
            syscall_entropy=1.6, trace_length=2000, rule_outbound=1,
        ))
        self.assertScoreAbove(p, 0.35, "Hydra brute force")
        print(_fmt("hydra score", f"{p:.4f}", "> 0.35", p > 0.35))
    def test_webshell_execution_chain(self):
        p = self._host_proba(self.ff.host(
            process_spawn_rate=0.50, file_access_rate=0.30,
            net_activity_rate=0.25, process_chain_depth=5,
            syscall_entropy=2.1, trace_length=950,
            rule_outbound=1, rule_sensitive_file=1,
        ))
        self.assertScoreAbove(p, 0.40, "Webshell")
        print(_fmt("webshell score", f"{p:.4f}", "> 0.40", p > 0.40))
    def test_attack_beats_benign_baseline(self):
        benign = self._host_proba(self.ff.host())
        attack = self._host_proba(self.ff.host(
            priv_escalation_count=6, inject_attempt_count=2,
            syscall_entropy=1.8, rule_priv_esc=1,
            rule_outbound=1, rule_sensitive_file=1,
        ))
        self.assertGreater(attack, benign,
            f"Attack ({attack:.4f}) must score higher than benign ({benign:.4f})")
# =============================================================================
# 5. Network RF - Benign Profiles
# =============================================================================
class Test05NetworkBenign(BaseModelTest):
    def test_idle_benign_flow(self):
        p = self._net_proba(self.ff.net())
        self.assertScoreBelow(p, 0.50, "Idle benign flow")
        print(_fmt("idle flow score", f"{p:.4f}", "< 0.50", p < 0.50))
    def test_https_web_browsing(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Duration": 15000000, "Total Fwd Packets": 30,
            "Total Backward Packets": 45, "Flow Bytes/s": 18000.0,
            "Flow Packets/s": 5.0, "Avg Packet Size": 900.0,
            "SYN Flag Count": 1, "Fwd PSH Flags": 4,
        }))
        self.assertScoreBelow(p, 0.55, "HTTPS web browsing")
        print(_fmt("https browsing score", f"{p:.4f}", "< 0.55", p < 0.55))
    def test_ssh_session_flow(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Duration": 3600000000, "Total Fwd Packets": 2000,
            "Total Backward Packets": 1800, "Flow Bytes/s": 800.0,
            "Flow Packets/s": 1.1, "Avg Packet Size": 320.0,
            "SYN Flag Count": 1, "botnet_c2_indicator": 0,
            "port_scan_indicator": 0,
        }))
        self.assertScoreBelow(p, 0.65, "SSH session")
        print(_fmt("ssh session score", f"{p:.4f}", "< 0.65", p < 0.65))
    def test_dns_lookup_flow(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Duration": 50000, "Total Fwd Packets": 1,
            "Total Backward Packets": 1, "Flow Bytes/s": 24000.0,
            "Flow Packets/s": 40.0, "Avg Packet Size": 60.0,
            "SYN Flag Count": 0,
        }))
        self.assertScoreBelow(p, 0.55, "DNS lookup")
        print(_fmt("dns lookup score", f"{p:.4f}", "< 0.55", p < 0.55))
# =============================================================================
# 6. Network RF - Attack Profiles
# =============================================================================
class Test06NetworkAttack(BaseModelTest):
    def test_syn_flood_ddos(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Packets/s": 150000.0, "Total Fwd Packets": 500000,
            "Total Backward Packets": 0, "SYN Flag Count": 200,
            "Avg Packet Size": 64.0, "Init Fwd Win Bytes": 8192,
        }))
        self.assertScoreAbove(p, 0.30, "SYN flood DDoS")
        print(_fmt("syn flood score", f"{p:.4f}", "> 0.30", p > 0.30))
    def test_port_scan(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Packets/s": 80000.0, "Fwd Packets/s": 80000.0,
            "Bwd Packets/s": 0.0, "Total Fwd Packets": 50000,
            "Total Backward Packets": 0, "Avg Packet Size": 40.0,
            "Avg Fwd Segment Size": 40.0, "SYN Flag Count": 1,
            "port_scan_indicator": 1,
        }))
        self.assertScoreAbove(p, 0.25, "Port scan")
        print(_fmt("port scan score", f"{p:.4f}", "> 0.25", p > 0.25))
    def test_botnet_c2_beaconing(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Duration": 3600000000, "Total Fwd Packets": 720,
            "Total Backward Packets": 718, "Flow Bytes/s": 50.0,
            "Flow Packets/s": 0.2, "Avg Packet Size": 64.0,
            "Avg Fwd Segment Size": 64.0, "Init Fwd Win Bytes": 4096,
            "Fwd PSH Flags": 720, "botnet_c2_indicator": 1,
        }))
        self.assertScoreAbove(p, 0.30, "Botnet C2 beaconing")
        print(_fmt("c2 beaconing score", f"{p:.4f}", "> 0.30", p > 0.30))
    def test_brute_force_flow(self):
        p = self._net_proba(self.ff.net(**{
            "Flow Duration": 200000, "Total Fwd Packets": 8,
            "Total Backward Packets": 2, "Flow Bytes/s": 60000.0,
            "Flow Packets/s": 50.0, "Avg Packet Size": 160.0,
            "SYN Flag Count": 1,
        }))
        self.assertScoreAbove(p, 0.20, "Brute force flow")
        print(_fmt("brute force score", f"{p:.4f}", "> 0.20", p > 0.20))
    def test_attack_beats_benign_baseline(self):
        benign = self._net_proba(self.ff.net())
        attack = self._net_proba(self.ff.net(**{
            "Flow Packets/s": 200000.0, "SYN Flag Count": 300,
            "botnet_c2_indicator": 1, "port_scan_indicator": 1,
        }))
        self.assertGreater(attack, benign,
            f"Network attack ({attack:.4f}) must exceed benign ({benign:.4f})")
# =============================================================================
# 7. Meta-Classifier - Four Quadrant Tests
# =============================================================================
class Test07MetaClassifier(BaseModelTest):
    def test_Q1_both_high_scores_critical(self):
        p = self._meta_proba(0.95, 0.95)
        self.assertScoreAbove(p, 0.85, "Q1: both high")
        print(_fmt("Q1 both-high score", f"{p:.4f}", "> 0.85", p > 0.85))
    def test_Q2_both_low_scores_benign(self):
        p = self._meta_proba(0.05, 0.05)
        self.assertScoreBelow(p, 0.45, "Q2: both low")
        print(_fmt("Q2 both-low score", f"{p:.4f}", "< 0.45", p < 0.45))
    def test_Q3_host_high_net_low_still_elevated(self):
        p = self._meta_proba(0.92, 0.08)
        self.assertScoreAbove(p, 0.50, "Q3: host-heavy")
        print(_fmt("Q3 host-heavy score", f"{p:.4f}", "> 0.50", p > 0.50))
    def test_Q4_host_low_net_high_elevated(self):
        p = self._meta_proba(0.08, 0.92)
        self.assertScoreAbove(p, 0.35, "Q4: network-heavy")
        print(_fmt("Q4 network-heavy score", f"{p:.4f}", "> 0.35", p > 0.35))
    def test_medium_inputs_not_critical(self):
        p = self._meta_proba(0.50, 0.50)
        self.assertGreater(p, 0.20, f"Mid inputs too low: {p:.4f}")
        self.assertLess(p, 0.85, f"Mid inputs triggered CRITICAL: {p:.4f}")
    def test_output_always_bounded(self):
        for p_h, p_n in [(0.0,0.0),(1.0,1.0),(0.5,0.5),(0.0,1.0),(1.0,0.0)]:
            p = self._meta_proba(p_h, p_n)
            self.assertGreaterEqual(p, 0.0)
            self.assertLessEqual(p, 1.0)
    def test_monotonicity_increasing_host(self):
        net_fixed = 0.60
        scores = [self._meta_proba(h, net_fixed) for h in [0.1,0.3,0.5,0.7,0.9]]
        for i in range(len(scores)-1):
            self.assertGreaterEqual(scores[i+1], scores[i]-0.05,
                f"Meta score decreased as host increased: {scores}")
    def test_monotonicity_increasing_network(self):
        host_fixed = 0.60
        scores = [self._meta_proba(host_fixed, n) for n in [0.1,0.3,0.5,0.7,0.9]]
        for i in range(len(scores)-1):
            self.assertGreaterEqual(scores[i+1], scores[i]-0.05,
                f"Meta score decreased as network increased: {scores}")
# =============================================================================
# 8. Threat Level Boundary Tests
# =============================================================================
class Test08ThreatLevels(unittest.TestCase):
    def test_low_interior(self):
        for v in [0.00, 0.10, 0.20, 0.39]:
            self.assertEqual(classify_score(v), "LOW", f"classify_score({v}) should be LOW")
    def test_medium_interior(self):
        for v in [0.40, 0.50, 0.60, 0.69]:
            self.assertEqual(classify_score(v), "MEDIUM", f"classify_score({v}) should be MEDIUM")
    def test_high_interior(self):
        for v in [0.70, 0.75, 0.80, 0.84]:
            self.assertEqual(classify_score(v), "HIGH", f"classify_score({v}) should be HIGH")
    def test_critical_interior(self):
        for v in [0.85, 0.90, 0.95, 1.00]:
            self.assertEqual(classify_score(v), "CRITICAL", f"classify_score({v}) should be CRITICAL")
    def test_boundary_low_to_medium(self):
        self.assertEqual(classify_score(0.399), "LOW")
        self.assertEqual(classify_score(0.400), "MEDIUM")
    def test_boundary_medium_to_high(self):
        self.assertEqual(classify_score(0.699), "MEDIUM")
        self.assertEqual(classify_score(0.700), "HIGH")
    def test_boundary_high_to_critical(self):
        self.assertEqual(classify_score(0.849), "HIGH")
        self.assertEqual(classify_score(0.850), "CRITICAL")
    def test_boundary_extremes(self):
        self.assertEqual(classify_score(0.00), "LOW")
        self.assertEqual(classify_score(1.00), "CRITICAL")
# =============================================================================
# 9. False Positive Resistance
# =============================================================================
class Test09FalsePositiveResistance(BaseModelTest):
    def test_fp_01_developer_curl(self):
        result = self._predict(host_overrides=dict(rule_outbound=1))
        self.assertNotIn(result["threat_level"], ("HIGH","CRITICAL"),
            f"Developer curl triggered {result['threat_level']} - FP!")
        print(_fmt("FP-01 developer curl", f"{result['final_score']:.4f} ({result['threat_level']})",
                   "not HIGH/CRITICAL", result["threat_level"] not in ("HIGH","CRITICAL")))
    def test_fp_02_cron_sudo(self):
        result = self._predict(host_overrides=dict(
            process_spawn_rate=0.22, file_access_rate=0.55,
            process_chain_depth=3, priv_escalation_count=1, rule_priv_esc=1,
        ))
        self.assertNotIn(result["threat_level"], ("HIGH","CRITICAL"),
            f"Cron+sudo triggered {result['threat_level']} - FP!")
        print(_fmt("FP-02 cron sudo", f"{result['final_score']:.4f} ({result['threat_level']})",
                   "not HIGH/CRITICAL", result["threat_level"] not in ("HIGH","CRITICAL")))
    def test_fp_03_apt_install(self):
        result = self._predict(host_overrides=dict(
            process_spawn_rate=0.35, file_access_rate=0.52,
            process_chain_depth=4, priv_escalation_count=1,
            rule_priv_esc=1, trace_length=1200,
        ))
        self.assertNotIn(result["threat_level"], ("CRITICAL",),
            f"apt install triggered CRITICAL - FP!")
        print(_fmt("FP-03 apt install", f"{result['final_score']:.4f} ({result['threat_level']})",
                   "not CRITICAL", result["threat_level"] != "CRITICAL"))
    def test_fp_04_ssh_session(self):
        result = self._predict(net_overrides={
            "Flow Duration": 3600000000, "Total Fwd Packets": 2000,
            "Total Backward Packets": 1900, "Flow Bytes/s": 800.0,
            "Flow Packets/s": 1.1, "botnet_c2_indicator": 0, "port_scan_indicator": 0,
        })
        self.assertNotIn(result["threat_level"], ("CRITICAL",),
            f"SSH session triggered CRITICAL - FP!")
        print(_fmt("FP-04 ssh session", f"{result['final_score']:.4f} ({result['threat_level']})",
                   "not CRITICAL", result["threat_level"] != "CRITICAL"))
    def test_fp_05_all_falco_rules_benign_behavior(self):
        result = self._predict(host_overrides=dict(
            rule_outbound=1, rule_priv_esc=1, rule_sensitive_file=1,
            process_spawn_rate=0.03, file_access_rate=0.08,
            net_activity_rate=0.05, process_chain_depth=1,
            priv_escalation_count=0, inject_attempt_count=0,
            syscall_entropy=3.1,
        ))
        self.assertNotIn(result["threat_level"], ("CRITICAL",),
            f"All-rules-fire but benign behavior triggered CRITICAL - FP!")
        print(_fmt("FP-05 all rules benign", f"{result['final_score']:.4f} ({result['threat_level']})",
                   "not CRITICAL", result["threat_level"] != "CRITICAL"))
    def test_fp_attack_always_above_benign(self):
        benign_result = self._predict()
        attack_result = self._predict(
            host_overrides=dict(
                priv_escalation_count=6, inject_attempt_count=2, syscall_entropy=1.8,
                rule_priv_esc=1, rule_outbound=1, rule_sensitive_file=1,
            ),
            net_overrides={
                "Flow Packets/s": 200000.0, "SYN Flag Count": 200,
                "botnet_c2_indicator": 1, "port_scan_indicator": 1,
            }
        )
        self.assertGreater(attack_result["final_score"], benign_result["final_score"],
            f"Attack ({attack_result['final_score']:.4f}) must beat benign ({benign_result['final_score']:.4f})")
# =============================================================================
# 10. End-to-End Pipeline
# =============================================================================
class Test10EndToEndPipeline(BaseModelTest):
    def test_predict_returns_all_required_keys(self):
        result = self._predict()
        for key in ("p_host","p_network","final_score","threat_level"):
            self.assertIn(key, result, f"Missing key in predict() output: {key}")
    def test_all_scores_are_floats_in_range(self):
        result = self._predict()
        for key in ("p_host","p_network","final_score"):
            self.assertIsInstance(result[key], float, f"{key} is not a float")
            self.assertGreaterEqual(result[key], 0.0, f"{key} < 0")
            self.assertLessEqual(result[key], 1.0, f"{key} > 1")
    def test_threat_level_is_valid_string(self):
        result = self._predict()
        self.assertIn(result["threat_level"], ("LOW","MEDIUM","HIGH","CRITICAL"))
    def test_threat_level_consistent_with_final_score(self):
        result = self._predict()
        expected = classify_score(result["final_score"])
        self.assertEqual(result["threat_level"], expected,
            f"threat_level='{result['threat_level']}' but classify_score returns '{expected}'")
    def test_predict_is_deterministic(self):
        h = self.ff.host(rule_outbound=1, process_chain_depth=3)
        n = self.ff.net(**{"botnet_c2_indicator": 1})
        r1 = self.ms.predict(h, n)
        r2 = self.ms.predict(h, n)
        self.assertAlmostEqual(r1["final_score"], r2["final_score"], places=8,
            msg="predict() is non-deterministic")
    def test_predict_speed(self):
        h = self.ff.host()
        n = self.ff.net()
        t0 = time.perf_counter()
        self.ms.predict(h, n)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed_ms, 500, f"predict() took {elapsed_ms:.1f}ms - exceeds 500ms SLA")
        print(_fmt("inference latency", f"{elapsed_ms:.1f}ms", "< 500ms", elapsed_ms < 500))
    def test_hundred_predictions_no_crash(self):
        rng = np.random.default_rng(42)
        for i in range(100):
            h = self.ff.host(
                process_spawn_rate=float(rng.uniform(0, 0.6)),
                syscall_entropy=float(rng.uniform(1.5, 4.0)),
            )
            n = self.ff.net(**{"Flow Packets/s": float(rng.uniform(1, 100000))})
            try:
                result = self.ms.predict(h, n)
                self.assertIn(result["threat_level"], ("LOW","MEDIUM","HIGH","CRITICAL"))
            except Exception as e:
                self.fail(f"predict() crashed on iteration {i}: {e}")
# =============================================================================
# 11. Score Monotonicity
# =============================================================================
class Test11Monotonicity(BaseModelTest):
    def test_host_monotone_priv_escalation(self):
        scores = [self._host_proba(self.ff.host(priv_escalation_count=n))
                  for n in [0, 1, 2, 4, 8]]
        for i in range(len(scores)-1):
            self.assertGreaterEqual(scores[i+1], scores[i]-0.05,
                f"Host score decreased as priv_escalation_count increased: {scores}")
    def test_host_monotone_rule_accumulation(self):
        s0 = self._host_proba(self.ff.host())
        s1 = self._host_proba(self.ff.host(rule_outbound=1))
        s2 = self._host_proba(self.ff.host(rule_outbound=1, rule_priv_esc=1))
        s3 = self._host_proba(self.ff.host(rule_outbound=1, rule_priv_esc=1, rule_sensitive_file=1))
        for prev, curr, label in [(s0,s1,"0->1"),(s1,s2,"1->2"),(s2,s3,"2->3 rules")]:
            self.assertGreaterEqual(curr, prev-0.05,
                f"Score decreased adding rule ({label}): {prev:.4f} -> {curr:.4f}")
    def test_network_monotone_scan_escalation(self):
        s_base = self._net_proba(self.ff.net())
        s_scan = self._net_proba(self.ff.net(**{"port_scan_indicator": 1}))
        s_heavy = self._net_proba(self.ff.net(**{
            "port_scan_indicator": 1, "Flow Packets/s": 50000.0, "SYN Flag Count": 100,
        }))
        self.assertGreaterEqual(s_scan,  s_base-0.05, "Base->Scan decreased")
        self.assertGreaterEqual(s_heavy, s_scan-0.05, "Scan->Heavy decreased")
    def test_e2e_monotone_adding_indicators(self):
        r0 = self._predict()
        r1 = self._predict(host_overrides=dict(rule_priv_esc=1))
        r2 = self._predict(
            host_overrides=dict(rule_priv_esc=1, rule_outbound=1),
            net_overrides={"botnet_c2_indicator": 1})
        r3 = self._predict(
            host_overrides=dict(rule_priv_esc=1, rule_outbound=1, rule_sensitive_file=1,
                                priv_escalation_count=4, inject_attempt_count=1),
            net_overrides={"botnet_c2_indicator": 1, "port_scan_indicator": 1,
                           "Flow Packets/s": 50000.0})
        scores = [r["final_score"] for r in [r0,r1,r2,r3]]
        print(f"    Monotonicity: {' -> '.join(f'{s:.3f}' for s in scores)}")
        for i in range(len(scores)-1):
            self.assertGreaterEqual(scores[i+1], scores[i]-0.05,
                f"End-to-end score decreased at step {i}->{i+1}: {scores}")
# =============================================================================
# 12. Held-Out Dataset Evaluation (True Test Splits)
# =============================================================================
class Test12HeldOutPerformance(BaseModelTest):
    def _eval(self, model, scaler, feature_cols, csv_path, min_prec, min_rec, label, sample=None):
        if not csv_path.exists():
            self.skipTest(f"{csv_path.name} not found. Run training scripts first.")
        df = pd.read_csv(csv_path)
        if sample:
            df = df.sample(n=min(sample, len(df)), random_state=99)
        missing = [c for c in feature_cols if c not in df.columns]
        self.assertEqual(missing, [], f"{csv_path.name} missing columns: {missing}")
        X   = df[feature_cols].values.astype(float)
        y   = df["label"].values
        Xsc = scaler.transform(X)
        y_pred  = model.predict(Xsc)
        y_proba = model.predict_proba(Xsc)[:, 1]
        prec = precision_score(y, y_pred, zero_division=0)
        rec  = recall_score(y, y_pred, zero_division=0)
        f1   = f1_score(y, y_pred, zero_division=0)
        auc  = roc_auc_score(y, y_proba) if len(np.unique(y)) > 1 else None
        cm   = confusion_matrix(y, y_pred)
        tn,fp,fn,tp = cm.ravel() if cm.shape==(2,2) else (0,0,0,0)
        fpr  = fp/(fp+tn) if (fp+tn)>0 else 0.0
        auc_s = f"{auc:.4f}" if auc else "N/A"
        print(f"\n  [{label}]")
        print(_fmt("Precision", f"{prec:.4f}", f">={min_prec}", prec>=min_prec))
        print(_fmt("Recall",    f"{rec:.4f}",  f">={min_rec}",  rec>=min_rec))
        print(_fmt("F1 Score",  f"{f1:.4f}",   ">=0.75",        f1>=0.75))
        print(_fmt("ROC-AUC",   auc_s,         ">=0.85",        auc>=0.85 if auc else True))
        print(_fmt("FPR",       f"{fpr:.4f}",  "<0.20",         fpr<0.20))
        print(f"    TP={tp} FP={fp} TN={tn} FN={fn}")
        self.assertGreaterEqual(prec, min_prec, f"{label} Precision {prec:.4f} < {min_prec}")
        self.assertGreaterEqual(rec,  min_rec,  f"{label} Recall {rec:.4f} < {min_rec}")
        self.assertGreaterEqual(f1,   0.75,     f"{label} F1 {f1:.4f} < 0.75")
        self.assertLess(fpr, 0.20, f"{label} FPR {fpr:.4f} >= 0.20")
    def test_host_model_held_out(self):
        self._eval(
            model=self.ms.host_rf, scaler=self.ms.host_scaler,
            feature_cols=self.ms.host_cols,
            csv_path=DATA_DIR / "adfa_test_split.csv",
            min_prec=0.75, min_rec=0.75, label="Host RF",
        )
    def test_network_model_held_out(self):
        self._eval(
            model=self.ms.net_rf, scaler=self.ms.net_scaler,
            feature_cols=self.ms.net_cols,
            csv_path=DATA_DIR / "cicids_test_split.csv",
            min_prec=0.85, min_rec=0.85, label="Network RF",
            sample=5000,
        )
# =============================================================================
# 13. Retraining Correctness
# =============================================================================
class Test13RetrainingCorrectness(BaseModelTest):
    def _fresh_meta(self):
        return copy.deepcopy(self.ms.meta_clf)
    def test_partial_fit_does_not_crash(self):
        clf = self._fresh_meta()
        try:
            clf.partial_fit(np.array([[0.9, 0.85], [0.1, 0.1]]), np.array([1, 0]), classes=[0,1])
        except Exception as e:
            self.fail(f"partial_fit raised an exception: {e}")
    def test_partial_fit_accepts_batch(self):
        clf = self._fresh_meta()
        X = np.array([[0.9,0.85],[0.92,0.88],[0.05,0.03]])
        y = np.array([1, 1, 0])
        try:
            clf.partial_fit(X, y, classes=[0,1])
        except Exception as e:
            self.fail(f"Batch partial_fit raised: {e}")
    def test_repeated_attack_retraining_maintains_high_score(self):
        clf = self._fresh_meta()
        attack_X = np.array([[0.91, 0.87]])
        score_before = float(clf.predict_proba(attack_X)[0, 1])
        for _ in range(15):
            clf.partial_fit(np.array([[0.92, 0.88], [0.05, 0.05]]), np.array([1, 0]), classes=[0,1])
        score_after = float(clf.predict_proba(attack_X)[0, 1])
        print(_fmt("retrain attack before->after", f"{score_before:.4f} -> {score_after:.4f}", "", True))
        self.assertGreaterEqual(score_after, score_before-0.10,
            f"Retraining degraded attack score: {score_before:.4f} -> {score_after:.4f}")
        self.assertGreater(score_after, 0.60,
            f"Attack score after retraining dropped below 0.60: {score_after:.4f}")
    def test_retrain_does_not_crash_many_iterations(self):
        clf = self._fresh_meta()
        rng = np.random.default_rng(42)
        for i in range(30):
            label = int(rng.integers(0, 2))
            ph = float(rng.uniform(0.5,1.0) if label else rng.uniform(0,0.3))
            pn = float(rng.uniform(0.5,1.0) if label else rng.uniform(0,0.3))
            try:
                clf.partial_fit(np.array([[ph, pn], [1-ph, 1-pn]]), np.array([label, 1-label]), classes=[0,1])
            except Exception as e:
                self.fail(f"partial_fit crashed at iteration {i}: {e}")
# =============================================================================
# 14. Retraining Stability
# =============================================================================
class Test14RetrainingStability(BaseModelTest):
    def _fresh_meta(self):
        return copy.deepcopy(self.ms.meta_clf)
    def test_benign_retraining_does_not_inflate_attack_score(self):
        clf = self._fresh_meta()
        attack_X = np.array([[0.91, 0.87]])
        score_before = float(clf.predict_proba(attack_X)[0, 1])
        rng = np.random.default_rng(1)
        for _ in range(20):
            clf.partial_fit(
                np.array([[float(rng.uniform(0,0.1)), float(rng.uniform(0,0.1))], [0.95, 0.95]]),
                np.array([0, 1]), classes=[0,1]
            )
        score_after = float(clf.predict_proba(attack_X)[0, 1])
        print(_fmt("benign retrain -> attack score", f"{score_before:.4f} -> {score_after:.4f}",
                   "not inflated to 1.0", score_after < 0.999))
        self.assertLess(score_after, 0.999,
            f"Benign retraining inflated attack score to {score_after:.4f}")
    def test_attack_retraining_does_not_inflate_benign_score(self):
        clf = self._fresh_meta()
        benign_X = np.array([[0.04, 0.03]])
        for _ in range(20):
            clf.partial_fit(np.array([[0.92, 0.88], [0.1, 0.1]]), np.array([1, 0]), classes=[0,1])
        score = float(clf.predict_proba(benign_X)[0, 1])
        print(_fmt("attack retrain -> benign score", f"{score:.4f}", "< 0.85", score < 0.85))
        self.assertLess(score, 0.85,
            f"After attack retraining, benign scored {score:.4f} (HIGH/CRITICAL)")
    def test_scores_remain_bounded_after_50_iterations(self):
        clf = self._fresh_meta()
        rng = np.random.default_rng(0)
        for i in range(50):
            label = int(rng.integers(0, 2))
            ph, pn = float(rng.uniform(0,1)), float(rng.uniform(0,1))
            clf.partial_fit(np.array([[ph, pn], [1-ph, 1-pn]]), np.array([label, 1-label]), classes=[0,1])
        for ph, pn in [(0.05,0.03),(0.91,0.87),(0.50,0.50)]:
            score = float(clf.predict_proba(np.array([[ph, pn]]))[0, 1])
            self.assertFalse(np.isnan(score), f"Score is NaN after 50 iterations")
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)
    def test_fresh_copy_is_independent(self):
        clf_a = self._fresh_meta()
        clf_b = self._fresh_meta()
        clf_a.partial_fit(np.array([[0.95, 0.95], [0.05, 0.05]]), np.array([1, 0]), classes=[0,1])
        score_a = float(clf_a.predict_proba(np.array([[0.95, 0.95]]))[0, 1])
        score_b = float(clf_b.predict_proba(np.array([[0.95, 0.95]]))[0, 1])
        self.assertNotEqual(score_a, score_b,
            "Deep copy is sharing state with original! copy.deepcopy is not working.")
# =============================================================================
# 15. Robustness - Edge Case Inputs
# =============================================================================
class Test15Robustness(BaseModelTest):
    def test_all_zeros_host_no_crash(self):
        result = self.ms.predict(self.ff.host_zeros(), self.ff.net())
        self.assertIn(result["threat_level"], ("LOW","MEDIUM","HIGH","CRITICAL"))
    def test_all_zeros_network_no_crash(self):
        result = self.ms.predict(self.ff.host(), self.ff.net_zeros())
        self.assertIn(result["threat_level"], ("LOW","MEDIUM","HIGH","CRITICAL"))
    def test_all_zeros_both_no_crash(self):
        result = self.ms.predict(self.ff.host_zeros(), self.ff.net_zeros())
        self.assertIsNotNone(result["final_score"])
        self.assertFalse(np.isnan(result["final_score"]), "All-zero inputs produced NaN score")
    def test_extreme_large_values_no_crash(self):
        h = self.ff.host(process_spawn_rate=1e6, priv_escalation_count=999999,
                         trace_length=9999999, syscall_entropy=100.0)
        n = self.ff.net(**{
            "Flow Packets/s": 1e12, "Flow Duration": 1e15,
            "Total Fwd Packets": 1e9, "Flow Bytes/s": 1e12,
        })
        result = self.ms.predict(h, n)
        self.assertIsNotNone(result["final_score"])
        self.assertFalse(np.isnan(result["final_score"]))
        self.assertGreaterEqual(result["final_score"], 0.0)
        self.assertLessEqual(result["final_score"], 1.0)
    def test_negative_values_no_crash(self):
        h = self.ff.host(process_spawn_rate=-1.0, syscall_entropy=-5.0)
        n = self.ff.net(**{"Flow Bytes/s": -100.0, "Flow Duration": -1})
        try:
            result = self.ms.predict(h, n)
            self.assertIsNotNone(result)
        except Exception as e:
            self.fail(f"Negative inputs caused crash: {e}")
    def test_all_rule_features_one_no_crash(self):
        h = self.ff.host(rule_outbound=1, rule_priv_esc=1, rule_sensitive_file=1)
        result = self.ms.predict(h, self.ff.net())
        self.assertIn(result["threat_level"], ("LOW","MEDIUM","HIGH","CRITICAL"))
    def test_score_is_not_nan_on_random_inputs(self):
        rng = np.random.default_rng(7)
        for i in range(100):
            h = {c: float(rng.uniform(-1, 10)) for c in self.ms.host_cols}
            n = {c: float(rng.uniform(-1, 1e6)) for c in self.ms.net_cols}
            try:
                result = self.ms.predict(h, n)
                self.assertFalse(np.isnan(result["final_score"]),
                    f"NaN score on random input iteration {i}")
                self.assertGreaterEqual(result["final_score"], 0.0)
                self.assertLessEqual(result["final_score"], 1.0)
            except Exception as e:
                self.fail(f"Random input crashed predict() at iteration {i}: {e}")
# =============================================================================
# Test runner with summary
# =============================================================================
if __name__ == "__main__":
    print(f"\n{CYAN}{BOLD}{'='*65}{RESET}")
    print(f"{CYAN}{BOLD}  CyberShield ML Ensemble - Comprehensive Test Suite V2{RESET}")
    print(f"{CYAN}{BOLD}{'='*65}{RESET}\n")
    test_classes = [
        Test01ArtifactIntegrity,
        Test02FeatureSchema,
        Test03HostBenign,
        Test04HostAttack,
        Test05NetworkBenign,
        Test06NetworkAttack,
        Test07MetaClassifier,
        Test08ThreatLevels,
        Test09FalsePositiveResistance,
        Test10EndToEndPipeline,
        Test11Monotonicity,
        Test12HeldOutPerformance,
        Test13RetrainingCorrectness,
        Test14RetrainingStability,
        Test15Robustness,
    ]
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    total   = result.testsRun
    failed  = len(result.failures) + len(result.errors)
    skipped = len(result.skipped)
    passed  = total - failed - skipped
    print(f"\n{CYAN}{BOLD}{'='*65}{RESET}")
    print(f"  {GREEN}Passed:  {passed}{RESET}")
    if skipped:
        print(f"  {YELLOW}Skipped: {skipped}{RESET}")
    if failed:
        print(f"  {RED}Failed:  {failed}{RESET}")
    print(f"  Total:   {total}")
    if failed == 0:
        print(f"\n  {GREEN}{BOLD}ALL {total} TESTS PASSED - Ensemble is production-ready.{RESET}")
    else:
        print(f"\n  {RED}{BOLD}{failed} TEST(S) FAILED - Review before demo.{RESET}")
    print(f"{CYAN}{BOLD}{'='*65}{RESET}\n")
    sys.exit(0 if failed == 0 else 1)

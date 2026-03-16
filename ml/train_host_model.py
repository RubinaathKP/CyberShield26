import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns

# ── Load features ─────────────────────────────────────────────────────
df = pd.read_csv('data/adfa_features.csv')

FEATURE_COLS = [
    'process_spawn_rate', 'file_access_rate', 'net_activity_rate',
    'process_chain_depth', 'priv_escalation_count', 'inject_attempt_count',
    'syscall_entropy', 'trace_length',
    'rule_outbound', 'rule_priv_esc', 'rule_sensitive_file',
]

X = df[FEATURE_COLS].values
y = df['label'].values

# ── Inject synthetic "benign-but-has-rules" samples ──────────────────
# The RF would otherwise overfit: all Hydra/Meterpreter/Webshell traces
# carry rule_outbound=1, so max_depth=15 memorises that single flag as
# a deterministic attack signal. We inject realistic benign profiles that
# trigger one or more rule flags to break this spurious correlation.
# Feature order matches FEATURE_COLS exactly:
# [spawn, file, net, depth, priv, inject, entropy, len, out, prsc, file_r]
SYNTHETIC_BENIGN = np.array([
    # Developer curl / outbound scripts
    [0.02, 0.08, 0.22, 1, 0, 0, 2.8, 180,  1, 0, 0],
    [0.03, 0.07, 0.18, 2, 0, 0, 3.0, 220,  1, 0, 0],
    [0.01, 0.09, 0.30, 1, 0, 0, 2.9, 150,  1, 0, 0],
    [0.04, 0.10, 0.15, 2, 0, 0, 2.7, 300,  1, 0, 0],
    # Cron with sudo
    [0.22, 0.55, 0.01, 3, 1, 0, 3.0, 1100, 0, 1, 0],
    [0.18, 0.48, 0.02, 3, 1, 0, 3.1, 900,  0, 1, 0],
    [0.25, 0.60, 0.01, 4, 1, 0, 2.9, 1200, 0, 1, 0],
    # apt install / package manager (all three flags, benign behavior)
    [0.30, 0.52, 0.02, 4, 1, 0, 3.2, 900,  1, 1, 1],
    [0.28, 0.50, 0.01, 3, 1, 0, 3.0, 800,  1, 1, 1],
    [0.35, 0.55, 0.03, 5, 1, 0, 3.1, 1100, 1, 1, 1],
    # SSH login
    [0.01, 0.05, 0.12, 2, 0, 0, 2.7, 200,  1, 0, 0],
    [0.02, 0.04, 0.10, 2, 0, 0, 2.6, 180,  1, 0, 0],
    # All three rules fire but truly benign: low entropy 3.x, no inject, short chain
    [0.03, 0.08, 0.05, 1, 0, 0, 3.1, 350,  1, 1, 1],
    [0.04, 0.07, 0.04, 1, 0, 0, 2.9, 330,  1, 1, 1],
    [0.02, 0.09, 0.06, 1, 0, 0, 3.0, 360,  1, 1, 1],
], dtype=float)
SYNTHETIC_LABELS = np.zeros(len(SYNTHETIC_BENIGN), dtype=int)

# ── Train/test split (on real data only for honest eval) ──────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, stratify=y, random_state=42
)

# Train set = real stratified split + all synthetic benign rows
X_train_aug = np.vstack([X_train, SYNTHETIC_BENIGN])
y_train_aug  = np.concatenate([y_train, SYNTHETIC_LABELS])

# ── Scale features ────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train_aug)
X_test_sc  = scaler.transform(X_test)

# ── SMOTE oversampling ────────────────────────────────────────────────
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train_sc, y_train_aug)
print(f'After SMOTE — train size: {len(X_train_bal)}')

# ── Train Random Forest ───────────────────────────────────────────────
# max_depth=8 prevents single rule-flag memorisation
host_rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=8,
    min_samples_leaf=4,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)
host_rf.fit(X_train_bal, y_train_bal)

# ── Evaluate ──────────────────────────────────────────────────────────
y_pred  = host_rf.predict(X_test_sc)
y_proba = host_rf.predict_proba(X_test_sc)[:, 1]

print('\n── Host RF Classification Report ──')
print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))
print(f'ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}')

# Confusion matrix plot
Path('models').mkdir(exist_ok=True)
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'])
plt.title('Host RF Confusion Matrix')
plt.savefig('models/host_rf_confusion.png', dpi=120, bbox_inches='tight')
plt.close()

# Feature importance
importances = pd.Series(host_rf.feature_importances_, index=FEATURE_COLS)
importances.sort_values().plot(kind='barh')
plt.title('Host RF Feature Importances')
plt.savefig('models/host_rf_importances.png', dpi=120, bbox_inches='tight')
plt.close()

# ── Save ──────────────────────────────────────────────────────────────
joblib.dump(host_rf,      'models/host_rf.pkl')
joblib.dump(scaler,       'models/host_scaler.pkl')
joblib.dump(FEATURE_COLS, 'models/host_feature_cols.pkl')
print('\nSaved: models/host_rf.pkl, host_scaler.pkl, host_feature_cols.pkl')

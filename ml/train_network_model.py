import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score

df = pd.read_csv('data/cicids_features.csv')

FEATURE_COLS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s',
    'Avg Packet Size', 'Avg Fwd Segment Size', 'Init Fwd Win Bytes',
    'SYN Flag Count', 'Fwd PSH Flags', 'URG Flag Count',
    'botnet_c2_indicator', 'port_scan_indicator',
]

X = df[FEATURE_COLS].values
y = df['label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, stratify=y, random_state=42
)

scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train)
X_test_sc  = scaler.transform(X_test)

net_rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=5,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)
net_rf.fit(X_train_sc, y_train)

y_pred  = net_rf.predict(X_test_sc)
y_proba = net_rf.predict_proba(X_test_sc)[:, 1]

print('\n── Network RF Classification Report ──')
print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))
print(f'ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}')

Path('models').mkdir(exist_ok=True)
joblib.dump(net_rf,        'models/net_rf.pkl')
joblib.dump(scaler,        'models/net_scaler.pkl')
joblib.dump(FEATURE_COLS,  'models/net_feature_cols.pkl')
print('Saved: models/net_rf.pkl, net_scaler.pkl, net_feature_cols.pkl')

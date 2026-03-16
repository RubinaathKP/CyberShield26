"""
augment_cicids.py  —  adds synthetic attack profiles to cicids_features.csv
that are underrepresented in CIC-IDS 2017:
  - Botnet C2 beaconing (long duration, very low packet count, c2_indicator=1)
  - Brute-force micro-bursts (short flows, high packet rate, small packets)
"""
import pandas as pd
import numpy as np
from pathlib import Path

CSV = Path('data/cicids_features.csv')

df = pd.read_csv(CSV)

# ── Confirm columns ───────────────────────────────────────────────────
COLS = df.columns.tolist()
print('Columns:', COLS)

rng = np.random.default_rng(42)

def make_row(overrides):
    """Build a single feature row from defaults + overrides."""
    defaults = {c: 0.0 for c in COLS}
    # sensible baseline
    defaults.update({
        'Flow Duration':            8_000_000,
        'Total Fwd Packets':        10,
        'Total Backward Packets':   8,
        'Flow Bytes/s':             1000.0,
        'Flow Packets/s':           5.0,
        'Fwd Packets/s':            2.5,
        'Bwd Packets/s':            2.5,
        'Avg Packet Size':          400.0,
        'Avg Fwd Segment Size':     380.0,
        'Init Fwd Win Bytes':       65535,
        'SYN Flag Count':           1,
        'Fwd PSH Flags':            2,
        'URG Flag Count':           0,
        'botnet_c2_indicator':      0,
        'port_scan_indicator':      0,
        'label':                    0,
    })
    defaults.update(overrides)
    return defaults

# ── Botnet C2 beaconing ───────────────────────────────────────────────
# Long duration (hours), tiny packets, very low pps, c2_indicator=1
n_c2 = 3000
c2_rows = []
for _ in range(n_c2):
    row = make_row({
        'Flow Duration':          float(rng.uniform(3_000_000_000, 7_200_000_000)),
        'Total Fwd Packets':      int(rng.integers(2, 12)),
        'Total Backward Packets': int(rng.integers(2, 12)),
        'Flow Bytes/s':           float(rng.uniform(5.0, 120.0)),
        'Flow Packets/s':         float(rng.uniform(0.05, 0.5)),
        'Fwd Packets/s':          float(rng.uniform(0.02, 0.25)),
        'Bwd Packets/s':          float(rng.uniform(0.02, 0.25)),
        'Avg Packet Size':        float(rng.uniform(40.0, 120.0)),
        'Avg Fwd Segment Size':   float(rng.uniform(40.0, 100.0)),
        'Init Fwd Win Bytes':     int(rng.integers(2048, 8192)),
        'Fwd PSH Flags':          int(rng.integers(1, 10)),
        'SYN Flag Count':         1,
        'botnet_c2_indicator':    1,
        'port_scan_indicator':    0,
        'label':                  1,
    })
    c2_rows.append(row)

# ── Brute-force micro-burst ───────────────────────────────────────────
# Short flows, high pps, small packets, low byte count
n_bf = 3000
bf_rows = []
for _ in range(n_bf):
    pps = float(rng.uniform(30.0, 200.0))
    row = make_row({
        'Flow Duration':          float(rng.uniform(50_000, 500_000)),
        'Total Fwd Packets':      int(rng.integers(4, 20)),
        'Total Backward Packets': int(rng.integers(1, 6)),
        'Flow Bytes/s':           float(rng.uniform(20_000, 120_000)),
        'Flow Packets/s':         pps,
        'Fwd Packets/s':          pps * 0.75,
        'Bwd Packets/s':          pps * 0.25,
        'Avg Packet Size':        float(rng.uniform(80.0, 220.0)),
        'Avg Fwd Segment Size':   float(rng.uniform(80.0, 200.0)),
        'Init Fwd Win Bytes':     int(rng.integers(4096, 32768)),
        'SYN Flag Count':         int(rng.integers(1, 3)),
        'Fwd PSH Flags':          0,
        'botnet_c2_indicator':    0,
        'port_scan_indicator':    0,
        'label':                  1,
    })
    bf_rows.append(row)

augment_df = pd.DataFrame(c2_rows + bf_rows, columns=COLS)
df_out = pd.concat([df, augment_df], ignore_index=True)
df_out.to_csv(CSV, index=False)
print(f'Augmented cicids_features.csv: {len(df)} → {len(df_out)} rows')
print(f'  C2 beaconing rows added: {n_c2}')
print(f'  Brute-force rows added:  {n_bf}')
print(f'  Attack label ratio: {df_out["label"].mean():.3f}')

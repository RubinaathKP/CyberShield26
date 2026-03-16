import pandas as pd
import numpy as np
from pathlib import Path

# Real dataset path
PARQUET_FILE = 'data/cic-ids/cic-collection.parquet'

# ── Features available in the parquet (no leading spaces, different names) ──
# Parquet schema uses: 'Avg Packet Size', 'Init Fwd Win Bytes', 'Fwd PSH Flags'
# instead of CSV names: 'Average Packet Size', 'Init_Win_bytes_forward', 'PSH Flag Count'
KEEP_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Avg Packet Size',         # maps to 'Average Packet Size' in original guide
    'Avg Fwd Segment Size',
    'Init Fwd Win Bytes',      # maps to 'Init_Win_bytes_forward'
    'SYN Flag Count',
    'Fwd PSH Flags',           # best proxy for 'PSH Flag Count' in this parquet
    'URG Flag Count',
    'ClassLabel',              # label column (not 'Label')
]


def load_and_clean(parquet_path: str) -> pd.DataFrame:
    print(f'Loading {parquet_path}...')
    df = pd.read_parquet(parquet_path, columns=KEEP_FEATURES, engine='pyarrow')

    # Replace inf with NaN, then drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Binary label: 0 = Benign, 1 = Attack
    df['label'] = (df['ClassLabel'] != 'Benign').astype(int)
    df.drop(columns=['ClassLabel'], inplace=True)

    # ── Derived features ─────────────────────────────────────────────
    # Port scan indicator: high packets/s + low bytes/packet
    pps_q90 = df['Flow Packets/s'].quantile(0.90)
    pkt_q10 = df['Avg Packet Size'].quantile(0.10)
    df['port_scan_indicator'] = (
        (df['Flow Packets/s'] > pps_q90) &
        (df['Avg Packet Size'] < pkt_q10)
    ).astype(int)

    # Botnet C2 indicator: long-duration, very-low-packet flows (beacon signature)
    dur_q90 = df['Flow Duration'].quantile(0.90)
    df['botnet_c2_indicator'] = (
        (df['Flow Duration'] > dur_q90) &
        (df['Total Fwd Packets'] + df['Total Backward Packets'] < 10)
    ).astype(int)

    return df


def build_dataset() -> pd.DataFrame:
    df = load_and_clean(PARQUET_FILE)

    print(f'\nTotal rows loaded: {len(df):,}')
    print(f'Benign: {(df["label"]==0).sum():,}')
    print(f'Attack: {(df["label"]==1).sum():,}')

    # Undersample to ~300k each class (parquet has ~7M benign, ~2M attack)
    benign_count = (df['label'] == 0).sum()
    attack_count = (df['label'] == 1).sum()
    benign  = df[df['label'] == 0].sample(n=min(300_000, benign_count), random_state=42)
    attacks = df[df['label'] == 1].sample(n=min(300_000, attack_count), random_state=42)
    df = pd.concat([benign, attacks], ignore_index=True).sample(frac=1, random_state=42)

    print(f'\nAfter undersampling: {len(df):,} rows')
    Path('data').mkdir(exist_ok=True)
    df.to_csv('data/cicids_features.csv', index=False)
    print('Saved to data/cicids_features.csv')
    return df


if __name__ == '__main__':
    build_dataset()

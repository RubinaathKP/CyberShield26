"""
generate_test_splits.py
=======================
Generates held-out test split CSVs for Test12 (HeldOut Evaluation):
  - data/adfa_test_split.csv   (20% stratified hold-out from adfa_features.csv)
  - data/cicids_test_split.csv (20% stratified hold-out from cicids_features.csv)

Run once before the test suite:
    python ml/generate_test_splits.py
"""
import sys
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

def make_split(src: Path, dst: Path, label=""):
    if not src.exists():
        print(f"[SKIP] {src.name} not found.")
        return
    df = pd.read_csv(src)
    _, test = train_test_split(df, test_size=0.20, stratify=df["label"], random_state=42)
    test.to_csv(dst, index=False)
    labels = test["label"].value_counts().to_dict()
    print(f"[{label}] {len(test)} rows saved to {dst.name}  |  labels: {labels}")

if __name__ == "__main__":
    make_split(DATA / "adfa_features.csv",    DATA / "adfa_test_split.csv",   "Host  ")
    make_split(DATA / "cicids_features.csv",  DATA / "cicids_test_split.csv", "Network")
    print("Done.")

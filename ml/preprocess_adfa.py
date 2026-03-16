import os
import re
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter

# Real dataset root (nested one extra level)
ADFA_ROOT = Path('data/ADFA-LD/ADFA-LD')

# ── Syscall ID constants ──────────────────────────────────────────────
EXEC_SYSCALLS    = {59}          # execve
SPAWN_SYSCALLS   = {56, 59}      # clone, execve
FILE_SYSCALLS    = {0, 1, 2, 3}  # read, write, open, close
NET_SYSCALLS     = {41, 42, 43}  # socket, connect, accept
PRIV_SYSCALLS    = {105, 106}    # setuid, setgid
INJECT_SYSCALLS  = {101}         # ptrace

# ── Heuristic rule triggers per attack category ───────────────────────
RULE_TRIGGERS = {
    'Adduser':           {'rule_priv_esc': 1, 'rule_outbound': 0, 'rule_file': 1},
    'Hydra-FTP':         {'rule_priv_esc': 0, 'rule_outbound': 1, 'rule_file': 0},
    'Hydra-SSH':         {'rule_priv_esc': 0, 'rule_outbound': 1, 'rule_file': 0},
    'Java-Meterpreter':  {'rule_priv_esc': 1, 'rule_outbound': 1, 'rule_file': 1},
    'Meterpreter':       {'rule_priv_esc': 1, 'rule_outbound': 1, 'rule_file': 1},
    'Webshell':          {'rule_priv_esc': 0, 'rule_outbound': 1, 'rule_file': 1},
    'Benign':            {'rule_priv_esc': 0, 'rule_outbound': 0, 'rule_file': 0},
}


def parse_trace(filepath):
    """Read a syscall trace file and return list of integer syscall IDs."""
    with open(filepath, 'r') as f:
        content = f.read().strip()
    return [int(x) for x in content.split() if x.isdigit()]


def derive_features(syscalls, category):
    """
    Derive feature vector from raw syscall sequence.
    Returns a dict matching the ML feature schema.
    """
    total = len(syscalls)
    if total == 0:
        return None

    # ── Behavioral counts ──────────────────────────────────────────────
    spawn_count  = sum(1 for s in syscalls if s in SPAWN_SYSCALLS)
    exec_count   = sum(1 for s in syscalls if s in EXEC_SYSCALLS)
    file_count   = sum(1 for s in syscalls if s in FILE_SYSCALLS)
    net_count    = sum(1 for s in syscalls if s in NET_SYSCALLS)
    priv_count   = sum(1 for s in syscalls if s in PRIV_SYSCALLS)
    inject_count = sum(1 for s in syscalls if s in INJECT_SYSCALLS)

    # ── Rates (normalized by trace length) ────────────────────────────
    process_spawn_rate = spawn_count / total
    file_access_rate   = file_count  / total
    net_activity_rate  = net_count   / total

    # ── Process chain depth ────────────────────────────────────────────
    depth = 0
    in_exec_burst = False
    for s in syscalls:
        if s in EXEC_SYSCALLS:
            if not in_exec_burst:
                depth += 1
                in_exec_burst = True
        else:
            in_exec_burst = False
    process_chain_depth = depth

    # ── Syscall entropy (diversity of syscall types used) ──────────────
    counts = Counter(syscalls)
    probs  = np.array(list(counts.values())) / total
    syscall_entropy = -np.sum(probs * np.log2(probs + 1e-9))

    # ── Rule trigger features (heuristic) ──────────────────────────────
    rules = RULE_TRIGGERS.get(category, RULE_TRIGGERS['Benign'])

    return {
        'process_spawn_rate':     process_spawn_rate,
        'file_access_rate':       file_access_rate,
        'net_activity_rate':      net_activity_rate,
        'process_chain_depth':    process_chain_depth,
        'priv_escalation_count':  priv_count,
        'inject_attempt_count':   inject_count,
        'syscall_entropy':        syscall_entropy,
        'trace_length':           total,
        'rule_outbound':          rules['rule_outbound'],
        'rule_priv_esc':          rules['rule_priv_esc'],
        'rule_sensitive_file':    rules['rule_file'],
        'label':                  0 if category == 'Benign' else 1,
        'attack_category':        category,
    }


def dir_to_category(dirname: str) -> str:
    """
    Convert a real ADFA-LD attack directory name like 'Adduser_1' or
    'Hydra_FTP_3' to the canonical category key used in RULE_TRIGGERS:
    'Adduser', 'Hydra-FTP', 'Java-Meterpreter', 'Meterpreter', 'Webshell'.
    """
    # Strip trailing _<number>
    base = re.sub(r'_\d+$', '', dirname)      # 'Hydra_FTP_3' -> 'Hydra_FTP'
    # Normalise to match RULE_TRIGGERS: underscores → hyphens for multi-word,
    # but NOT for 'Web_Shell' which maps to 'Webshell'
    mapping = {
        'Adduser':          'Adduser',
        'Hydra_FTP':        'Hydra-FTP',
        'Hydra_SSH':        'Hydra-SSH',
        'Java_Meterpreter': 'Java-Meterpreter',
        'Meterpreter':      'Meterpreter',
        'Web_Shell':        'Webshell',
    }
    return mapping.get(base, base)


def build_dataset(adfa_root):
    """Walk ADFA-LD directory structure and build complete feature DataFrame."""
    records = []
    adfa_root = Path(adfa_root)

    # Benign traces — all files directly inside Training_Data_Master/
    benign_dir = adfa_root / 'Training_Data_Master'
    if benign_dir.exists():
        trace_files = list(benign_dir.rglob('*.txt'))
        if not trace_files:
            trace_files = [f for f in benign_dir.rglob('*') if f.is_file()]
        for f in trace_files:
            syscalls = parse_trace(f)
            feat = derive_features(syscalls, 'Benign')
            if feat:
                records.append(feat)
        print(f'Loaded {len(records)} benign traces from Training_Data_Master')

    # Attack traces — each attack category is a group of dirs like 'Adduser_1'
    attack_dir = adfa_root / 'Attack_Data_Master'
    if attack_dir.exists():
        attack_before = len(records)
        for category_dir in sorted(attack_dir.iterdir()):
            if category_dir.is_dir():
                category = dir_to_category(category_dir.name)
                # trace files are directly inside each category_N dir
                trace_files = list(category_dir.rglob('*.txt'))
                if not trace_files:
                    trace_files = [f for f in category_dir.rglob('*') if f.is_file()]
                for f in trace_files:
                    syscalls = parse_trace(f)
                    feat = derive_features(syscalls, category)
                    if feat:
                        records.append(feat)
        print(f'Loaded {len(records) - attack_before} attack traces from Attack_Data_Master')

    if not records:
        print('WARNING: No traces found under:', adfa_root)
        return pd.DataFrame()

    df = pd.DataFrame(records)
    print(f'\nDataset built: {len(df)} traces, {df["label"].sum()} attacks')
    print(df['attack_category'].value_counts())
    return df


if __name__ == '__main__':
    Path('data').mkdir(exist_ok=True)
    df = build_dataset(ADFA_ROOT)
    if not df.empty:
        df.to_csv('data/adfa_features.csv', index=False)
        print('Saved to data/adfa_features.csv')

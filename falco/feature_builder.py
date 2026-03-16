import time
import math
from collections import defaultdict, Counter

# ── Syscall event type sets ────────────────────────────────────────
SPAWN_EVTS  = {'clone', 'execve', 'fork', 'vfork', 'execveat'}
NET_EVTS    = {'connect', 'socket', 'accept', 'accept4', 'bind'}
FILE_EVTS   = {'open', 'openat', 'read', 'write', 'close', 'creat'}
PRIV_EVTS   = {'setuid', 'setgid', 'setresuid', 'setresgid'}
INJECT_EVTS = {'ptrace', 'process_vm_readv', 'process_vm_writev'}
MMAP_EVTS   = {'mmap', 'mmap2', 'mprotect', 'mremap'}


class EntityWindow:
    """Accumulates Falco events for one entity over a time window."""

    def __init__(self):
        self.events    = []
        self.start_ts  = time.time()
        # Rule flags are sticky — once set they stay 1 for the window
        self.rule_outbound       = 0
        self.rule_priv_esc       = 0
        self.rule_sensitive_file = 0
        # Process chain depth tracking
        self._pid_depths  = {}   # pid → depth
        self.max_depth    = 1

    def add(self, raw: dict):
        """Ingest one raw event dict from forwarder.py."""
        self.events.append(raw)

        # Update rule flags
        rule = raw.get('rule', '')
        if 'OUTBOUND'       in rule: self.rule_outbound       = 1
        if 'PRIV_ESC'       in rule: self.rule_priv_esc       = 1
        if 'SENSITIVE_FILE' in rule: self.rule_sensitive_file = 1

        # Track process chain depth via fork/execve events
        if raw.get('evt_type') in SPAWN_EVTS:
            pid  = raw.get('proc_pid',  0)
            ppid = raw.get('proc_ppid', 0)
            parent_depth = self._pid_depths.get(ppid, 1)
            self._pid_depths[pid] = parent_depth + 1
            self.max_depth = max(self.max_depth, parent_depth + 1)

    def to_vector(self, entity_id: str) -> dict:
        """Emit a complete ML-ready feature vector for this window."""
        total = max(len(self.events), 1)

        # ── Event type counts ─────────────────────────────────────
        evt_types = [e.get('evt_type', '') for e in self.events]
        spawn  = sum(1 for e in evt_types if e in SPAWN_EVTS)
        net    = sum(1 for e in evt_types if e in NET_EVTS)
        filea  = sum(1 for e in evt_types if e in FILE_EVTS)
        priv   = sum(1 for e in evt_types if e in PRIV_EVTS)
        inj    = sum(1 for e in evt_types if e in INJECT_EVTS)
        mmap   = sum(1 for e in evt_types if e in MMAP_EVTS)

        # ── Syscall entropy (over proc_name distribution) ─────────
        names  = [e.get('proc_name', '') for e in self.events if e.get('proc_name')]
        counts = Counter(names)
        n      = max(len(names), 1)
        probs  = [v / n for v in counts.values()]
        entropy = -sum(p * math.log2(p + 1e-9) for p in probs)

        # ── Unique syscall ratio ───────────────────────────────────
        unique_ratio = len(counts) / total

        # ── Repeat ratio ──────────────────────────────────────────
        repeats = sum(
            1 for i in range(1, len(evt_types))
            if evt_types[i] == evt_types[i - 1]
        )
        repeat_ratio = repeats / max(total - 1, 1)

        return {
            'entity_id':    entity_id,
            'source':       'falco',
            'window_start': self.start_ts,
            'window_end':   time.time(),
            'host_features': {
                'process_spawn_rate':    round(spawn  / total, 6),
                'file_access_rate':      round(filea  / total, 6),
                'net_activity_rate':     round(net    / total, 6),
                'process_chain_depth':   min(self.max_depth, 10),
                'priv_escalation_count': priv,
                'inject_attempt_count':  inj,
                'mmap_count':            mmap,
                'syscall_entropy':       round(entropy, 4),
                'unique_syscall_ratio':  round(unique_ratio, 6),
                'repeat_ratio':          round(repeat_ratio, 6),
                'trace_length':          total,
                'rule_outbound':         self.rule_outbound,
                'rule_priv_esc':         self.rule_priv_esc,
                'rule_sensitive_file':   self.rule_sensitive_file,
            },
            # net_features filled from concurrent network flow data by API
            'net_features': None,
        }


class FeatureWindowBuilder:
    """
    Manages per-entity windows. Entities are identified by
    'proc_name:user_name' to track each process/user combination
    independently.
    """

    def __init__(self, window_seconds: float = 60):
        self.window_seconds = window_seconds
        self.windows: dict = defaultdict(EntityWindow)

    def ingest(self, raw: dict) -> list:
        """
        Add one event. Returns a list of completed feature vectors
        (empty list if no window has closed yet).
        """
        entity_id = (
            f"{raw.get('proc_name', 'unknown')}"
            f":{raw.get('user_name', 'unknown')}"
        )

        win = self.windows[entity_id]
        win.add(raw)

        ready = []
        if time.time() - win.start_ts >= self.window_seconds:
            ready.append(win.to_vector(entity_id))
            # Reset window for this entity
            self.windows[entity_id] = EntityWindow()

        return ready

    def force_flush(self) -> list:
        """
        Force all open windows to emit immediately.
        Used during graceful shutdown or demo injection.
        """
        vectors = []
        for entity_id, win in self.windows.items():
            if win.events:
                vectors.append(win.to_vector(entity_id))
        self.windows.clear()
        return vectors

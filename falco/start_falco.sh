#!/bin/bash
set -e
REPO_DIR=~/cybershield
cd $REPO_DIR
source venv/bin/activate

echo '================================================='
echo '  CyberShield — Starting Falco Pipeline'
echo '================================================='

# ── 1. Auto-detect driver ──────────────────────────────────────
if ls /sys/kernel/btf/vmlinux &>/dev/null; then
    DRIVER='modern_ebpf'
    echo "[falco] BTF available → using modern_ebpf driver"
else
    DRIVER='kmod'
    echo "[falco] No BTF → using kmod driver"
fi

# ── 2. Ensure Redis is running ─────────────────────────────────
sudo service redis-server start 2>/dev/null || true
redis-cli ping || {
    echo '[falco] ERROR: Redis is not running'
    echo '        Run: sudo service redis-server start'
    exit 1
}
echo '[falco] Redis: OK'

# ── 3. Copy custom rules to Falco rules directory ─────────────
sudo cp $REPO_DIR/falco/cybershield_rules.yaml /etc/falco/
echo '[falco] Rules file installed to /etc/falco/'

# ── 4. Start API server in background if not already running ──
if ! curl -s http://localhost:8000/metrics > /dev/null 2>&1; then
    echo '[falco] Starting API server...'
    uvicorn api.main:app --host 0.0.0.0 --port 8000 &
    sleep 3
fi
echo '[falco] API server: OK'

# ── 5. Start Falco piped to forwarder ─────────────────────────
echo '[falco] Starting Falco with driver:' $DRIVER
echo '[falco] Piping output to forwarder.py...'
echo ''

sudo falco \
    --rules-file /etc/falco/falco_rules.yaml \
    --rules-file /etc/falco/cybershield_rules.yaml \
    --option engine.kind=$DRIVER \
    --json-output \
    --json-include-output-property output_fields \
    2>/dev/null \
| python3 $REPO_DIR/falco/forwarder.py

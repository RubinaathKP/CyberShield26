#!/bin/bash
set -e   # exit on any error
echo '================================================='
echo '  CyberShield — Linux Laptop Setup'
echo '================================================='

# ── 1. System packages ─────────────────────────────────────────
sudo apt update && sudo apt install -y \
    python3-pip python3-venv redis-server \
    git curl unzip build-essential \
    linux-headers-$(uname -r)

# ── 2. Redis ───────────────────────────────────────────────────
sudo systemctl enable redis-server
sudo systemctl start redis-server
redis-cli ping || { echo 'ERROR: Redis failed to start'; exit 1; }

# ── 3. Falco repository ────────────────────────────────────────
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
  | sudo gpg --dearmor \
  -o /usr/share/keyrings/falco-archive-keyring.gpg

echo 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main' \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt update
# During install: select driver based on kernel check output below
sudo apt install -y falco

# ── 4. Verify Falco installed ──────────────────────────────────
falco --version || { echo 'ERROR: Falco install failed'; exit 1; }

# ── 5. Clone repo ──────────────────────────────────────────────
git clone https://github.com/YOUR_USERNAME/cybershield.git ~/cybershield
cd ~/cybershield

# ── 6. Python environment ──────────────────────────────────────
python3 -m venv venv
source venv/bin/activate
pip install scikit-learn imbalanced-learn pandas numpy \
    joblib shap fastapi uvicorn redis flask requests

# ── 7. Kernel compatibility check ─────────────────────────────
echo ''
echo '─── Kernel Check ───────────────────────────────'
echo 'Kernel version:' $(uname -r)
ls /sys/kernel/btf/vmlinux 2>/dev/null \
  && echo 'BTF available  → recommended driver: modern_ebpf' \
  || echo 'No BTF         → recommended driver: kmod'
echo '────────────────────────────────────────────────'
echo 'Setup complete. Next: bash falco/start_falco.sh'

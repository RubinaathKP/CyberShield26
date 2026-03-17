# SyscallSentinel — Complete Setup & Demo Guide

## FILES (all prefixed ss_ — no conflicts with old files)
- ss_server.js      → Backend (port 4000)
- ss_dashboard.html → SOC Dashboard (SyscallSentinel)
- ss_bank.html      → Original bank site (attack entry)
- ss_decoy.html     → Honeypot decoy site
- ss_db.json        → Auto-created on first run

---

## STEP 1 — DOWNLOAD FILES
In Firefox, download all 4 files from Claude.
They land in ~/Downloads/

---

## STEP 2 — CREATE FRESH FOLDER
Open terminal:
  mkdir -p ~/CyberShield26/sentinel
  cd ~/CyberShield26/sentinel
  cp ~/Downloads/ss_server.js .
  cp ~/Downloads/ss_dashboard.html .
  cp ~/Downloads/ss_bank.html .
  cp ~/Downloads/ss_decoy.html .

---

## STEP 3 — INSTALL NODE PACKAGES
  cd ~/CyberShield26/sentinel
  npm init -y
  npm install express socket.io cors

---

## STEP 4 — RUN EVERYTHING (3 terminals)

Terminal 1 — SyscallSentinel backend:
  cd ~/CyberShield26/sentinel
  node ss_server.js
  → You should see: SyscallSentinel server → http://localhost:4000

Terminal 2 — Your existing kernel backend (already works):
  cd ~/CyberShield26
  python3 -m backend.api.main

Terminal 3 — Frontend server:
  cd ~/CyberShield26/sentinel
  python3 -m http.server 5500

---

## STEP 5 — OPEN BROWSER TABS

Tab 1 (Dashboard):  http://localhost:5500/ss_dashboard.html
Tab 2 (Bank site):  http://localhost:5500/ss_bank.html
Tab 3 (Decoy):      http://localhost:5500/ss_decoy.html  [opens auto on attack]

---

## HOW TO SIMULATE AN ATTACK (DEMO STEPS)

### ATTACK 1 — RCE (most impressive for panel)
1. Open ss_bank.html
2. Click preset: "💀 RCE — Reverse Shell"
3. Click "🚀 Launch Attack"
4. Watch: red result box appears → "THREAT DETECTED — RCE"
5. Wait 2 seconds → auto-redirects to ss_decoy.html
6. On decoy: type any email + password → click Sign In
7. Watch terminal on right log every keystroke
8. Switch to ss_dashboard.html → stats updated, timeline moved, event in table

### ATTACK 2 — SQLi
1. Back on ss_bank.html
2. Click "🗃 SQLi — Auth Bypass"  
3. Launch → redirected to decoy again
4. Dashboard shows SQLi count increasing

### ATTACK 3 — Normal (show false positive avoidance)
1. Click "✅ Normal Request"
2. Launch → green box, NO redirect
3. Dashboard score is LOW
4. Tell panel: "System correctly identifies benign traffic"

### ATTACK 4 — Scenario Engine (best for panel)
1. Go to ss_dashboard.html → click "🎯 Scenario Engine" tab
2. Click "👾 Meterpreter" button
3. Watch result appear below: type=METERPRETER, score=0.97, CRITICAL
4. Click "📡 C2 Beaconing" → another result
5. Click "🔍 Port Scan" → another
6. Switch to Overview tab → all 3 appear in timeline + vector chart

### ATTACK 5 — Kernel pipeline (show integration)
1. In Terminal 2, run:
   echo '{"output":"real attack","priority":"CRITICAL","rule":"Injected"}' | python3 -m backend.falco.forwarder
2. Dashboard shows KERNEL badge next to the event
3. Tell panel: "This came directly from our kernel-level monitor"

---

## WHERE TO SEE RESULTS ON DASHBOARD

### Overview Tab (Page 1):
- Top row: Total Alerts / Honeypot Events / Unique IPs / Scenarios Run
- Threat Activity Timeline: line chart updating live
- Attack Vectors: donut chart (RCE/SQLi/XSS/LFI/Scenario)
- Severity Distribution: CRITICAL/HIGH/LOW bars
- ML Threat Alerts table: columns are →
    Timestamp | Entity ID | Source (KERNEL/WEB/SCENARIO) | Type | Score | Level | XAI Analysis
- Honeypot Activity: list of attackers caught

### Live Detection Tab (Page 2):
- Live Alert Feed: every event scrolling in real time
- ML Model Training: retrain counts, accuracy, confidence bars per attack type
- Real-Time Threat Stream: bar chart of last 20 events
- Honeypot Monitor: table with IP / event type / path / log status

### Scenario Engine Tab (Page 3):
- 5 clickable scenario buttons (Port Scan / Meterpreter / C2 / Benign Admin / Hydra Brute)
- Result card shows after each execution: ID, type, score, XAI explanation
- Scenario History table at bottom

### Alert Feedback Tab (Page 4):
- Enter Alert ID (from ML Alerts table, e.g. EVT-0001)
- Click Yes/No for accuracy
- Optionally select corrected type + comment
- Submit → model accuracy updates
- Feedback chart shows accuracy trend over time

---

## PANEL DEMO SCRIPT (3 minutes)

"This is SyscallSentinel — our AI-powered kernel-level threat detection system."

[Show dashboard] "Our SOC dashboard monitors everything in real time."

[Switch to bank site] "This is a production web application being monitored."

[Click RCE preset → Launch] "I'm simulating a reverse shell attack."

[Redirect happens] "The kernel agent detected the threat and isolated the attacker in our honeypot."

[Show decoy terminal] "We capture everything — credentials, behavior, browser fingerprint."

[Switch back to dashboard] "The event appears here immediately — classified as RCE with 0.94 confidence."

[Click Scenario Engine → Meterpreter] "Our Scenario Engine tests the system against pre-configured vectors like Meterpreter sessions."

[Click Feedback tab] "Analysts can submit feedback to retrain the model — making it smarter over time."

[Click Retrain] "One click retrains the model with all captured threat data."

---

## CONNECTING KERNEL BACKEND

Your existing forwarder.py already calls /demo/analyze.
SyscallSentinel's ss_server.js ALSO handles /demo/analyze on port 4000.

To route your kernel to SyscallSentinel instead of port 8000:
Edit ~/CyberShield26/backend/falco/forwarder.py
Change: "http://127.0.0.1:8000/demo/analyze"
To:     "http://127.0.0.1:4000/demo/analyze"

Then kernel events will show as KERNEL badge on SyscallSentinel dashboard.

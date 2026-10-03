<div align="center">

# 🛡️ CyberDefense-AI

### AI-Powered Security Operations Center Platform

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.1-EE4C2C?style=flat-square&logo=pytorch)](https://pytorch.org)
[![Blockchain](https://img.shields.io/badge/Blockchain-Core_Testnet2-gold?style=flat-square)](https://coredao.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Real-time network attack detection · ML threat classification · Live incident response · Cyber Range**

[Live Demo](#demo-credentials) · [Quick Start](#quick-start) · [Architecture](#architecture)

</div>

---

## Overview

CyberDefense-AI is a full-stack Security Operations Center that detects, classifies, and responds to cyber attacks in real time. It monitors your network traffic, identifies attack patterns using machine learning, enriches threat data with external intelligence, and presents everything through a live SOC dashboard.

The project evolved from a simple ransomware file scanner into a complete defensive security platform — from PE file analysis to live network packet capture, honeypot traps, multi-signal incident correlation, and automated forensic evidence preservation with blockchain integrity verification.

---

## Core Capabilities

### 🔴 Real-Time Attack Detection

The platform monitors ALL network traffic arriving at your machine and detects attacks from other devices on the same network:

- **nmap port scans** — detected within 30 seconds (5 distinct ports threshold)
- **Brute force attacks** — SSH, RDP, FTP, SMB, Telnet (8 attempts in 60s)
- **SYN floods** — DoS attempt detection (50 SYNs/30s)
- **Stealth scans** — NULL scan, XMAS scan, FIN scan
- **C2 beaconing** — periodic callbacks to external IPs
- **Data exfiltration** — large outbound data bursts (20MB threshold)

When an attack is detected, the SOC dashboard shows a live incident card within seconds — attacker IP, geolocation, risk score, honeypot status, and response actions.

### 🦠 Malware & Ransomware Classification

Dual ML ensemble trained on 62,485 PE files:

| Model | Accuracy | Architecture |
|-------|----------|-------------|
| Random Forest | **99.62%** | 100 trees, 15 PE features |
| PyTorch DNN | **98.30%** | 4-layer: 128→64→32→1, BatchNorm |

Features: `Machine`, `DebugSize`, `DebugRVA`, `MajorImageVersion`, `MajorOSVersion`, `ExportRVA`, `ExportSize`, `IatVRA`, `MajorLinkerVersion`, `MinorLinkerVersion`, `NumberOfSections`, `SizeOfStackReserve`, `DllCharacteristics`, `ResourceSize`, `BitcoinAddresses`

Every prediction includes SHAP explainability — which features drove the classification and by how much.

### 🌐 Network Intrusion Detection (ML)

Separate ensemble trained on CICIDS2017 + CICIDS2018 + NSL-KDD:

| Model | Accuracy | Classes |
|-------|----------|---------|
| Network RF | **93-94%** | 8-class attack classification |
| Network DNN | **85-86%** | LayerNorm — stable training, no oscillation |
| Binary RF Anomaly | **93.3% / 95.9% F1** | Attack vs Benign detection |
| NSL-KDD DNN | **97.38%** | DoS, Port Scan, Brute Force, Infiltration |

Attack classes: `BENIGN · PORT_SCAN · BRUTE_FORCE · DOS · DDOS · BOTNET · WEB_ATTACK · INFILTRATION`

### 🍯 Active Honeypot

7 decoy files that look like real sensitive data but contain completely fake content. A Watchdog filesystem monitor watches the honeypot directory — any process that opens, reads, or modifies a decoy file triggers an immediate alert.

Decoy files: `financial_report_Q4.xlsx` · `employee_data.xlsx` · `passwords.txt` · `backup.zip` · `credentials.db` · `ssh_private_key.pem` · `database_backup.sql`

### 🔍 Threat Intelligence

Every detected attacker IP is automatically enriched:

- **AbuseIPDB** — abuse confidence score, total reports, Tor exit node check
- **Shodan** — open ports, running services, CVEs on attacker's machine
- **VirusTotal** — file hash against 70+ AV engines, malware family

### ⛓ Blockchain Integrity

Every HIGH-severity threat and forensic evidence bundle is recorded on **Core Testnet2** (Chain ID 1114). Analysts can verify any incident hash through the Blockchain page — proof that evidence hasn't been tampered with.

---

## Architecture

```
Attack from network               File dropped in watched/
        │                                  │
        ▼                                  ▼
Network Monitor                     File Monitor
(raw socket / scapy)              (Watchdog observer)
        │                                  │
        ▼                                  ▼
Detection Engines               Extract PE Features
(PORT_SCAN, BRUTE_FORCE,        (pefile / entropy)
 SYN_FLOOD, NULL/XMAS/FIN)             │
        │                               ▼
        ▼                    RF + DNN Ensemble
IP Geolocation                 (threat_scorer.py)
(ipinfo.io → ip-api.com)              │
        │                              ▼
        ▼                    MITRE ATT&CK Mapping
Threat Intel                           │
(AbuseIPDB, Shodan)                    ▼
        │                    Auto-Quarantine + Blockchain
        ▼
Risk Scorer ←── Honeypot Trigger ──── Threat Correlator
(0-100 score)                         (multi-signal)
        │
        ▼
Incident Manager ──→ WebSocket ──→ SOC Dashboard
        │             (live_incident)
        ▼
Forensic Evidence
+ Blockchain Hash
```

---

## ML Models

### Ransomware Detection
Trained on 62,485 PE files (ransomware + benign samples).

```python
# Ensemble prediction
rf_prob  = rf_model.predict_proba(features)[0][1]   # 60% weight
dnn_prob = pytorch_dnn(features_tensor).item()       # 40% weight
score    = (rf_prob * 0.60 + dnn_prob * 0.40) * 100
```

### Network IDS
Trained on CICIDS2017 (2.8M flows) + CICIDS2018 (6.6M flows).

Key fixes in the training pipeline:
- **LayerNorm** replaces BatchNorm in DNN — eliminates train/eval accuracy oscillation
- **Disk checkpointing** (`torch.save`) — best model saved to disk, isolated from RAM tensor state
- **Binary RF Anomaly Detector** replaces Isolation Forest — 93.3% vs 43% accuracy
- **Stratified sampling before merge** — avoids OOM with 9M+ row datasets

### Risk Score (0–100)

Transparent, factor-based scoring — not hard-coded:

| Signal | Max Contribution |
|--------|-----------------|
| ML Detection | 25 pts |
| Honeypot Trigger | 25 pts |
| Network Attack | 25 pts |
| File Activity | 15 pts |
| Process Anomaly | 5 pts |
| Multi-signal Correlation | 5 pts |

---

## Cyber Range

A safe, controlled attack simulation environment. All simulations flow through the **same detection pipeline** as real attacks — not scripted fake sequences.

```bash
# Interactive terminal
python cyberdefense_cli.py

# Direct commands
python cyberdefense_cli.py simulate ransomware
python cyberdefense_cli.py simulate portscan
python cyberdefense_cli.py simulate brute-force
python cyberdefense_cli.py simulate phishing
python cyberdefense_cli.py simulate suspicious-process
python cyberdefense_cli.py simulate data-exfiltration
python cyberdefense_cli.py simulate honeypot
python cyberdefense_cli.py simulate full-attack      # 7-stage complete attack
python cyberdefense_cli.py status
python cyberdefense_cli.py incidents
```

**Full attack simulation stages:**
1. Reconnaissance (port scan)
2. Authentication brute force
3. Suspicious process spawned
4. Honeypot access
5. Malicious file deployment (ML detection)
6. Data exfiltration
7. Ransom note dropped

---

## SOC Dashboard

The live SOC dashboard updates in real time via WebSocket:

- **Live Incident Card** — slides in on attack detection with attacker geo, risk score, threat intel
- **Metric cards** — Files Scanned, Ransomware, High Risk, Incidents, Honeypot Hits, System Health
- **Live Alerts feed** — real-time security events
- **Incidents panel** — correlated incidents with click-through
- **Threat timeline** — area chart of historical scores
- **Detection heatmap** — 16-week calendar view

**Incident Detail Page** (7 tabs):
1. Overview — attack details, risk factor breakdown
2. Attacker — IP, geo, MAC, AbuseIPDB + Shodan threat intel
3. AI Investigate — AI-assisted investigation from actual telemetry
4. Timeline — chronological event sequence
5. Attack Graph — nodes/edges from source to response
6. Evidence — forensic bundle with blockchain hash verification
7. Replay — recorded events replayed in order

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
cp example.env .env      # edit .env with your keys
python app.py
```

### Run as Administrator (full packet capture — catches nmap)
```powershell
backend\start_admin.bat
```

### Frontend
```powershell
cd frontend
npm install
npm run dev
```

### Train Network IDS Models (optional)
```
1. Open Jupyter: jupyter notebook
2. Open: notebooks/network_ids_v2.ipynb
3. Kernel → CyberDefense AI
4. Cell → Run All  (~15-20 min)
```

---

## Configuration

Copy `backend/example.env` to `backend/.env` and fill in:

```env
# Required
SECRET_KEY=your-secret-key

# Blockchain (Core Testnet2)
CONTRACT_ADDRESS=0x9807Ae60581B38611534d656f6a16AF28B846E17
WALLET_PRIVATE_KEY=your_wallet_key

# AI Chatbot (pick one — all free)
GEMINI_API_KEY=          # aistudio.google.com — recommended
GROQ_API_KEY=            # console.groq.com
OPENAI_API_KEY=          # paid

# Threat Intelligence (all optional, all free tier)
ABUSEIPDB_API_KEY=       # abuseipdb.com — 1000/day
SHODAN_API_KEY=          # shodan.io — 100/month
VIRUSTOTAL_API_KEY=      # virustotal.com — 500/day
IPINFO_TOKEN=            # ipinfo.io — 50k/month, better geo

# Email Alerts
EMAIL_ENABLED=false
EMAIL_SENDER=your@gmail.com
EMAIL_PASSWORD=gmail_app_password
EMAIL_RECEIVER=analyst@example.com

# Webhook (Slack/Discord)
# WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## External Services

| Service | Used For | Free Tier |
|---------|---------|-----------|
| ipinfo.io | IP geolocation (primary) | 50k req/month |
| ip-api.com | IP geolocation (fallback) | 45 req/min |
| AbuseIPDB | IP abuse reputation | 1,000 checks/day |
| Shodan | Host fingerprinting | 100 lookups/month |
| VirusTotal | File hash scanning | 500 req/day |
| Gemini 2.0 Flash | AI chatbot | Generous free tier |
| Groq Llama-3.3 | AI chatbot fallback | Free |
| Core Testnet2 | Blockchain logging | Free testnet |
| Gmail SMTP | Email alerts | Free |

---

## Demo Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | Full access |
| analyst | analyst123 | Read + scan |

**URLs after startup:**
- Dashboard: http://localhost:5173
- SOC War Room: http://localhost:5173/soc
- Cyber Lab: http://localhost:5173/lab
- Incidents: http://localhost:5173/incidents
- Backend API: http://localhost:5000

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10, Flask, Flask-SocketIO, JWT |
| ML (Ransomware) | scikit-learn RF, PyTorch DNN, SHAP |
| ML (Network IDS) | scikit-learn RF, PyTorch DNN (LayerNorm), Binary RF |
| Database | SQLite |
| Blockchain | Solidity, Web3.py, Core Testnet2 |
| Frontend | React 18, Vite, Tailwind CSS, Recharts |
| Network Capture | Scapy, psutil, Windows raw sockets |
| File Monitor | Watchdog |
| Email | Gmail SMTP |
| Reports | ReportLab (PDF) |

---

<div align="center">

Built by **Gagandeep Singh** — [@Shekhawat12082003](https://github.com/Shekhawat12082003)

*Started as a ransomware detector. Became a SOC.*

</div>

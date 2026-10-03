# 🛡️ CyberDefense-AI — AI-Powered SOC Platform

> A full-stack Security Operations Center built from scratch — real-time network attack detection, ML-powered classification, honeypot traps, threat intelligence enrichment, incident response automation, and a live cyber range for attack simulations.

**Developer:** Gagandeep Singh ([@Shekhawat12082003](https://github.com/Shekhawat12082003))

---

## What This Project Does

This started as a ransomware detector and evolved into a complete SOC platform. Here's everything that's been built:

---

### 🦠 Ransomware & Malware Detection (v1)

The original core — a dual ML ensemble trained on 62,485 PE files:

- **Random Forest** (99.62% accuracy) + **PyTorch DNN** (98.30% accuracy)
- Extracts 15 PE header features: `Machine`, `DebugSize`, `DllCharacteristics`, `BitcoinAddresses`, etc.
- SHAP explainability — every prediction shows which features drove the decision
- Auto-quarantine: files scoring above threshold are moved, XOR-encrypted, logged
- Blockchain logging: every HIGH threat gets a SHA-256 hash recorded on **Core Testnet2** (Chain ID 1114) — tamper-proof, verifiable
- File monitor watches `backend/watched/` with Watchdog — scans any dropped `.exe/.dll/.sys` automatically
- PDF incident reports generated with ReportLab
- Email alerts via Gmail SMTP when a HIGH threat is detected

---

### 🌐 Real-Time Network Intrusion Detection (v2)

The platform now monitors ALL network traffic hitting your machine and detects attacks from other devices:

- **8 detection engines**: Port Scan, Brute Force, SYN Flood, NULL Scan, XMAS Scan, FIN Scan, C2 Beacon, Data Exfiltration
- **Raw socket capture** (Windows) — catches nmap probes, rejected SYNs, stealth scans without needing Wireshark
- **Scapy sniffer** (when run as Administrator) — full packet-level capture
- **psutil fallback** — established connections when packet capture unavailable
- When an attack hits: automatically geolocates the attacker IP, calculates risk score, creates an incident, emits `live_incident` to the dashboard via WebSocket — all within seconds

**Network IDS ML Models** trained on CICIDS2017 + CICIDS2018 + NSL-KDD:
- Random Forest: 93-94% accuracy on 8 attack classes
- PyTorch DNN: 85-86% (LayerNorm architecture — no training oscillation)
- Binary RF Anomaly Detector: 93% accuracy, 95.9% F1 (replaced Isolation Forest which gave only 43%)
- Classes: `BENIGN · PORT_SCAN · BRUTE_FORCE · DOS · DDOS · BOTNET · WEB_ATTACK · INFILTRATION`

---

### 🚨 Live Incident Response

When any attack is detected (real or simulated), the SOC dashboard instantly shows:

- **Attacker card** with source IP highlighted in red
- **IP geolocation** — city, country, ISP, ASN (labeled APPROXIMATE, never fabricated)
- **Risk score 0–100** with transparent factor breakdown showing what contributed
- **6 response status badges**: DETECTED → HONEYPOT → ML ENGINE → QUARANTINE → EVIDENCE → BLOCKCHAIN
- **Detection timer** counting up from 0.00 seconds
- **Ports scanned** list for port scan attacks
- **Attack graph** — nodes and edges showing attacker → process → honeypot → files → ML → response

---

### 🔍 Threat Intelligence Enrichment

Every detected attacker IP is automatically enriched with:

- **AbuseIPDB** — abuse confidence score (0–100%), report count, whether it's a Tor exit node (free, 1000/day)
- **Shodan** — open ports on attacker's machine, running services, known CVEs, OS fingerprint (free 100/month)
- **VirusTotal** — file hash scanning against 70+ AV engines, malware family identification (free 500/day)

These run in background threads — results appear in the incident card and incident detail page without blocking detection.

---

### 🍯 Active Honeypot

7 decoy files that look like real sensitive data but are completely fake:

- `financial_report_Q4.xlsx`, `employee_data.xlsx`, `passwords.txt`, `backup.zip`, `credentials.db`, `ssh_private_key.pem`, `database_backup.sql`
- **Active filesystem watcher** (Watchdog) — any READ, OPEN, or WRITE to a decoy file immediately triggers an alert — even from the local machine
- When triggered: WebSocket event fires, honeypot trigger recorded in DB, incident risk score gets a +25 boost
- Simulations can deliberately trigger honeypots to demonstrate the detection chain

---

### 🔬 Cyber Range — Safe Attack Simulations

A controlled lab environment with 8 simulation types:

| Simulation | What it does |
|------------|-------------|
| `ransomware` | Drops synthetic PE files into `watched/` for ML detection |
| `portscan` | Generates port scan telemetry events |
| `brute-force` | Simulates auth attempt events on SSH/RDP |
| `phishing` | Email attachment → payload → C2 beacon chain |
| `suspicious-process` | Spawns fake malicious process with honeypot access |
| `data-exfiltration` | Simulates large outbound data + honeypot access |
| `honeypot` | Directly accesses decoy files |
| `full-attack` | 7-stage complete attack: Recon → Brute Force → Process → Honeypot → Files → Exfil → Ransom Note |

All simulations flow through the **same detection pipeline** as real attacks — they're not fake pre-scripted screens, they generate real events that the ML models, correlator, and risk scorer process.

**CLI terminal:**
```
python cyberdefense_cli.py simulate full-attack
python cyberdefense_cli.py simulate brute-force
python cyberdefense_cli.py status
python cyberdefense_cli.py incidents
```

---

### 📊 SOC Dashboard — Real-Time

The main dashboard shows everything live:

- **Live Incident Card** — slides in when any attack detected, shows attacker geo + risk score + threat intel + response status
- **8 metric cards**: Files Scanned, Ransomware, High Risk, Suspicious, Active Incidents, Honeypot Hits, System Health, Blockchain Mode
- **Live Security Alerts feed** — real-time WebSocket events from simulations and real attacks
- **Live Incidents panel** — correlated incidents with click-through to full detail
- **Threat Score Timeline** — area chart of historical detections
- **Detection Heatmap** — 16-week calendar view of activity
- **Network Events feed** — raw security events from all sources

---

### 🎯 Threat Correlation Engine

Individual events are correlated into high-confidence incidents:

- **Correlation dimensions**: time proximity, source IP, process identity, scenario ID
- **Signals combined**: ML prediction, file activity, honeypot trigger, network anomaly, process behavior
- **Risk score formula** (transparent, not hard-coded):
  - ML Detection: up to +25 points
  - File Activity: up to +15 points
  - Honeypot Trigger: up to +25 points
  - Network Attack: up to +25 points
  - Process Anomaly: up to +5 points
  - Multi-signal Correlation bonus: up to +5 points

---

### 🔒 Incident Detail View

Every incident has a 7-tab detail page:

1. **Overview** — attack details, risk score breakdown with factor bars, process info
2. **Attacker** — IP, geo, MAC note, threat intelligence (AbuseIPDB + Shodan)
3. **AI Investigate** — AI-assisted investigation using actual incident telemetry
4. **Timeline** — chronological event timeline with severity markers
5. **Attack Graph** — nodes/edges: source IP → process → honeypot/files → ML → response
6. **Evidence** — forensic bundle with SHA-256 hash recorded on blockchain for integrity
7. **Replay** — replay the actual recorded events in chronological order

---

### ⛓ Blockchain

Every high-severity threat and evidence bundle gets an immutable record:

- Smart contract `ThreatLogger.sol` deployed on **Core Testnet2** (Chain ID 1114)
- Functions: `logThreatSimple()`, `verifyHash()`, `getThreatByHash()`
- Analyst can verify any incident hash on the Blockchain page
- Evidence bundles: SHA-256 of the full forensic bundle stored on-chain
- Local fallback simulation when wallet balance is insufficient

---

### 🤖 AI Security Analyst Chatbot

Context-aware chatbot with live platform data injected:

- Providers in order: OpenAI GPT-4o-mini → Gemini 2.0 Flash (free) → Groq Llama-3.3-70b (free) → rule-based fallback
- Knows current threat stats, quarantine state, failed logins, blockchain mode
- Can answer: "what happened?", "why was this ransomware?", "how many threats today?"

---

### 🧪 What Was Trained

| Model | Dataset | Accuracy | Purpose |
|-------|---------|----------|---------|
| Random Forest | 62,485 PE files | 99.62% | Ransomware detection |
| PyTorch DNN | 62,485 PE files | 98.30% | Ransomware detection |
| Network RF | CICIDS2017 + 2018 | 93-94% | 8-class network attack |
| Network DNN | CICIDS2017 + 2018 | 85-86% | 8-class network attack |
| Binary RF | CICIDS2017 + 2018 | 93.3% | Anomaly detection |
| NSL-KDD RF | NSL-KDD | 97%+ | DoS/Scan/BruteForce |
| NSL-KDD DNN | NSL-KDD | 97.38% | DoS/Scan/BruteForce |

---

### 🔑 External APIs Used

| Service | Purpose | Free Tier |
|---------|---------|-----------|
| ipinfo.io | IP geolocation (primary, HTTPS) | 50k/month |
| ip-api.com | IP geolocation (fallback) | 45 req/min |
| Core Testnet2 | Blockchain logging | Free testnet |
| AbuseIPDB | IP abuse reputation | 1000/day |
| Shodan | Host fingerprinting | 100/month |
| VirusTotal | File hash scanning | 500/day |
| Gemini 2.0 Flash | AI chatbot | Free tier |
| Groq Llama-3.3 | AI chatbot fallback | Free tier |
| Gmail SMTP | Email alerts | Free |

---

### 🚀 How to Run

```powershell
# Terminal 1 — Backend (normal)
cd backend
venv\Scripts\activate
python app.py

# Terminal 1 — Backend (full packet capture, catches nmap)
backend\start_admin.bat

# Terminal 2 — Frontend
cd frontend
npm run dev

# Terminal 3 — Attack simulation
cd backend
python cyberdefense_cli.py simulate full-attack
```

**Add API keys to `backend/.env`:**
```env
GEMINI_API_KEY=...         # free at aistudio.google.com
ABUSEIPDB_API_KEY=...      # free at abuseipdb.com
SHODAN_API_KEY=...          # free at shodan.io
VIRUSTOTAL_API_KEY=...      # free at virustotal.com
IPINFO_TOKEN=...            # optional, free at ipinfo.io
```

---

### 🔐 Demo Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |

---

*Built by Gagandeep Singh — turning a hackathon ransomware detector into a full SOC platform.*

# Attack Testing Guide — CyberDefense AI SOC Platform

This document covers how to run real attack simulations against the platform from a Kali Linux VM and verify detection on the dashboard.

---

## Prerequisites

### 1. Network Setup

Both machines must be on the same network subnet.

| Machine | Role | IP |
|---|---|---|
| Windows (host) | Target / SOC Dashboard | `192.168.31.37` |
| Kali Linux VM | Attacker | `192.168.31.X` |

Verify connectivity from Kali before starting:
```bash
ping 192.168.31.37
```

### 2. Start the Backend as Administrator

For full packet capture (TShark + raw socket captures nmap SYN probes that never complete the handshake), the backend **must run as Administrator**.

```bat
# On Windows — double-click or run from cmd as Admin:
backend\start_admin.bat
```

Without Admin, only established connections are visible via psutil. nmap SYN scans, NULL scans, and XMAS scans will not be detected.

### 3. Start the Frontend

```bash
cd frontend
npm run dev
```

Dashboard: `http://localhost:5173`

### 4. Verify Capture is Active

Open the dashboard → **Network** tab → check capture mode shows `tshark` or `raw_socket+psutil`.

Or check the backend terminal — you should see:
```
[OK] Wireshark capture started automatically on Wi-Fi
[NET] Network monitor active — mode: tshark + psutil
   Monitoring traffic to: 192.168.31.37
   Port scan threshold:   5 ports in 30s
   Brute force threshold: 5 attempts in 60s
```

---

## Attack Simulations from Kali

### Attack 1 — Port Scan (nmap)

**Triggers**: `PORT_SCAN` alert on dashboard

```bash
# Basic SYN scan — fast, stealthy
nmap -sS 192.168.31.37

# Scan more ports — higher confidence detection
nmap -sS -p 1-500 --min-rate 100 192.168.31.37

# Aggressive scan with OS detection
nmap -A -T4 192.168.31.37

# Scan top 1000 ports at maximum speed
nmap -T5 192.168.31.37
```

**Expected on dashboard:**
- Alert type: `PORT SCAN`
- Attacker IP: your Kali IP
- Ports scanned count
- Risk score based on intensity
- Live Incident Card appears

---

### Attack 2 — Stealth Scans

**Triggers**: `NULL_SCAN`, `XMAS_SCAN`, `FIN_SCAN` alerts — these are detected instantly from individual packets

```bash
# NULL scan (TCP flags = 0) — very stealthy, evades basic firewalls
nmap -sN 192.168.31.37

# XMAS scan (FIN + PSH + URG flags set)
nmap -sX 192.168.31.37

# FIN scan
nmap -sF 192.168.31.37
```

**Expected on dashboard:**
- Alert type: `NULL SCAN` / `XMAS SCAN` / `FIN SCAN`
- Severity: HIGH
- Detected on first matching packet (no threshold needed)

---

### Attack 3 — Brute Force

**Triggers**: `BRUTE_FORCE` alert after 5+ auth attempts to same port

#### SSH brute force
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.31.37 ssh -t 4
```

#### HTTP login brute force (Flask API on port 5000)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  192.168.31.37 \
  http-post-form "/api/login:username=^USER^&password=^PASS^:Invalid" \
  -s 5000 -t 10
```

#### medusa alternative
```bash
medusa -h 192.168.31.37 -u admin -P /usr/share/wordlists/rockyou.txt -M ssh
```

**Expected on dashboard:**
- Alert type: `BRUTE FORCE`
- Target port: 22 (SSH) or 5000 (HTTP)
- Auth attempt count
- Attacker IP with geolocation (LOCAL NETWORK for LAN IP)

---

### Attack 4 — SYN Flood / DoS

**Triggers**: `SYN_FLOOD` alert after 20+ SYN packets in 5 seconds from same IP

```bash
# hping3 SYN flood
hping3 -S --flood -p 5000 192.168.31.37

# Target specific port
hping3 -S --flood -p 80 192.168.31.37

# Slower flood (still triggers, more realistic)
hping3 -S -i u10000 -p 5000 192.168.31.37
```

> ⚠️ Run for a few seconds only — `--flood` is very aggressive. Ctrl+C to stop.

**Expected on dashboard:**
- Alert type: `SYN FLOOD`
- Severity: HIGH
- SYN packet count in alert description

---

### Attack 5 — Data Exfiltration Simulation

**Triggers**: `DATA_EXFIL` alert (large outbound bursts)

```bash
# Simulate many rapid connections (exfil pattern)
for i in {1..50}; do
  curl -s http://192.168.31.37:5000/api/health &
done
wait

# Or use ab (Apache Bench) for HTTP flood
ab -n 500 -c 50 http://192.168.31.37:5000/
```

---

### Attack 6 — Full Kill Chain (APT simulation)

Run these in sequence with short pauses to simulate a real attack progression:

```bash
# Stage 1: Reconnaissance
nmap -sS -p 1-200 192.168.31.37

# Wait 10 seconds
sleep 10

# Stage 2: Stealth scan
nmap -sN 192.168.31.37

# Wait 10 seconds
sleep 10

# Stage 3: Brute force on discovered open port
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.31.37 http-post-form \
  "/api/login:username=^USER^&password=^PASS^:Invalid" -s 5000 -t 5

# Wait 10 seconds
sleep 10

# Stage 4: DoS
hping3 -S -c 100 -p 5000 192.168.31.37
```

**Expected**: Dashboard should show correlated incident across all 4 stages under the same attacker IP.

---

## Built-in Attack Simulator (same machine)

For quick testing without Kali, use the unified simulator:

```bash
# Interactive menu
.venv\Scripts\python.exe backend/attack_simulator.py

# Command-line: <attack_number> <aggressiveness 1-3> [target_ip]
.venv\Scripts\python.exe backend/attack_simulator.py 1 3 192.168.31.37   # Port scan HIGH
.venv\Scripts\python.exe backend/attack_simulator.py 2 2 192.168.31.37   # Brute force MEDIUM
.venv\Scripts\python.exe backend/attack_simulator.py 3 3 192.168.31.37   # SYN flood HIGH
.venv\Scripts\python.exe backend/attack_simulator.py 4 2 192.168.31.37   # Ransomware MEDIUM
.venv\Scripts\python.exe backend/attack_simulator.py 5 3 192.168.31.37   # APT kill chain HIGH
.venv\Scripts\python.exe backend/attack_simulator.py 6 2 192.168.31.37   # Data exfil MEDIUM
.venv\Scripts\python.exe backend/attack_simulator.py 7 2 192.168.31.37   # C2 beacon MEDIUM
```

### Aggressiveness levels

| Level | Effect |
|---|---|
| 1 — Low | Stays below detection thresholds. Use for baseline / false-positive testing. |
| 2 — Medium | Crosses thresholds, generates real alerts on dashboard. |
| 3 — High | Full intensity, guaranteed detection. |

---

## Detection Thresholds

| Attack Type | Threshold | Window |
|---|---|---|
| PORT_SCAN | 5+ distinct ports | 30 seconds |
| BRUTE_FORCE | 5+ auth attempts to same port | 60 seconds |
| SYN_FLOOD | 20+ SYN packets | 5 seconds |
| NULL_SCAN | 1 packet (immediate) | — |
| XMAS_SCAN | 1 packet (immediate) | — |
| FIN_SCAN | 1 packet (immediate) | — |
| DATA_EXFIL | 50 MB outbound | rolling |
| C2_BEACON | 10+ periodic connections | rolling |

Alert dedup window: **60 seconds** — same attack type from same IP won't re-alert within 1 minute.

---

## What You See on the Dashboard

When an attack is detected, the following happens in real time:

1. **Live Incident Card** appears on Dashboard with:
   - Attacker IP
   - Attack type and severity
   - Geolocation (approximate, labeled as LOCAL NETWORK for LAN IPs)
   - Risk score 0–100 with factor breakdown
   - Status pipeline: DETECTED → ML ENGINE → EVIDENCE → BLOCKCHAIN

2. **Alerts tab** shows the alert with:
   - Severity badge (CRITICAL / HIGH / MEDIUM / LOW)
   - Attack classification from ML model
   - Confidence percentage
   - Timestamp

3. **SOC page** shows:
   - Live security events feed
   - Threat level banner update
   - Attacker intelligence panel

4. **Incidents page** creates a full incident record with:
   - MITRE ATT&CK technique ID
   - Network evidence (ports hit, packet count)
   - Timeline of events

---

## Troubleshooting

### No alerts appearing

| Check | Fix |
|---|---|
| Backend not running as Admin | Run `backend\start_admin.bat` |
| Kali on different network | Make sure both on same subnet (`192.168.31.x`) |
| Windows Firewall blocking | Allow inbound on Windows Defender Firewall, or test with `ping` first |
| TShark not installed | Install Wireshark with TShark — `C:\Program Files\Wireshark\tshark.exe` |
| Npcap missing | Install Npcap during Wireshark setup (required for raw packet capture) |
| Attack below threshold | Use higher aggressiveness or more ports/attempts |

### Check backend terminal for detection logs

When an attack is detected, you should see:
```
[DETECT] PORT_SCAN from 192.168.31.X — running ML verification...
[ML OK] PORT_SCAN → model=PORT_SCAN conf=92.3%
🚨 live_incident → PORT_SCAN from 192.168.31.X | risk=78/100
```

If you see `[UNVERIFIED CANDIDATE]` or nothing at all — the backend is not running as Admin and raw socket capture is not active.

---

## Quick Reference

```bash
# Kali — confirm target reachable
ping 192.168.31.37

# Kali — quick port scan to trigger detection
nmap -sS -p 1-100 192.168.31.37

# Kali — instant stealth scan detection (1 packet)
nmap -sN 192.168.31.37

# Kali — brute force HTTP login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.31.37 \
  http-post-form "/api/login:username=^USER^&password=^PASS^:Invalid" -s 5000

# Kali — SYN flood
hping3 -S -c 50 -p 5000 192.168.31.37

# Windows — start backend with admin
backend\start_admin.bat

# Windows — run built-in simulator (interactive)
.venv\Scripts\python.exe backend/attack_simulator.py
```

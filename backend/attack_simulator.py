#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          CyberDefense AI — Unified Attack Simulator          ║
║          All attack types · Selectable aggressiveness        ║
╚══════════════════════════════════════════════════════════════╝

ATTACK TYPES:
  1  Port Scan          — TCP connection sweep across many ports
  2  Brute Force        — Rapid repeated auth attempts on a port
  3  SYN Flood / DoS    — High-volume connection flood
  4  Ransomware         — Safe file-based simulation (watched/)
  5  Mixed / APT        — Full kill-chain: file + network combined
  6  Data Exfiltration  — Large outbound connection bursts
  7  C2 Beacon          — Periodic callback pattern
  0  Exit

AGGRESSIVENESS LEVELS:
  1  Low    — Stays below detection thresholds (baseline / false-positive test)
  2  Medium — Crosses thresholds, generates alerts
  3  High   — Full-intensity, guaranteed detection
"""

import os
import sys
import time
import socket
import struct
import random
import string
import threading
import requests
from datetime import datetime

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
WATCHED_DIR = os.path.join(BASE_DIR, 'watched')
os.makedirs(WATCHED_DIR, exist_ok=True)

TARGET_IP   = "127.0.0.1"   # changed interactively
API_BASE    = "http://localhost:5000/api"

# ── Color helpers ──────────────────────────────────────────────
RED    = "\033[91m"
YEL    = "\033[93m"
GRN    = "\033[92m"
CYN    = "\033[96m"
BLD    = "\033[1m"
RST    = "\033[0m"

def banner(text, color=CYN):
    w = 62
    print(f"\n{color}{BLD}{'═'*w}{RST}")
    print(f"{color}{BLD}  {text}{RST}")
    print(f"{color}{BLD}{'═'*w}{RST}\n")

def step(msg, color=GRN):
    print(f"  {color}▶{RST}  {msg}")

def done(msg):
    print(f"\n  {GRN}✔  {msg}{RST}")

def warn(msg):
    print(f"  {YEL}⚠  {msg}{RST}")

def err(msg):
    print(f"  {RED}✘  {msg}{RST}")


# ══════════════════════════════════════════════════════════════
# AGGRESSIVENESS CONFIG
# Maps aggressiveness level → parameters for each attack
# ══════════════════════════════════════════════════════════════

AGG_LABELS = {1: f"{GRN}LOW{RST}", 2: f"{YEL}MEDIUM{RST}", 3: f"{RED}HIGH{RST}"}

AGGRESSIVENESS = {
    # Port Scan
    'port_scan': {
        1: {'ports': list(range(1, 30)),                                            'delay': 0.15, 'label': '29 ports  — below threshold'},
        2: {'ports': list(range(1, 80)) + [443, 8080, 3389, 22, 21, 25, 3306],     'delay': 0.08, 'label': '86 ports  — triggers detection'},
        3: {'ports': list(range(1, 200)) + [443, 8080, 3389, 22, 21, 25, 3306, 5432, 6379, 27017, 9200, 11211], 'delay': 0.02, 'label': '212 ports — full aggressive scan'},
    },
    # Brute Force
    'brute_force': {
        1: {'attempts': 15, 'delay': 0.4,  'label': '15 attempts — below threshold'},
        2: {'attempts': 40, 'delay': 0.15, 'label': '40 attempts — triggers detection'},
        3: {'attempts': 100,'delay': 0.05, 'label': '100 attempts — full throttle'},
    },
    # SYN Flood / DoS
    'syn_flood': {
        1: {'threads': 10,  'pkts_per_thread': 5,  'delay': 0.05, 'label': '50 packets  — below threshold'},
        2: {'threads': 30,  'pkts_per_thread': 10, 'delay': 0.02, 'label': '300 packets — triggers detection'},
        3: {'threads': 100, 'pkts_per_thread': 20, 'delay': 0.005,'label': '2000 packets — flood'},
    },
    # Ransomware (file-based, safe)
    'ransomware': {
        1: {'file_count': 2, 'delay': 2.0, 'label': '2 files  — light payload'},
        2: {'file_count': 5, 'delay': 1.2, 'label': '5 files  — standard payload'},
        3: {'file_count': 10,'delay': 0.4, 'label': '10 files — rapid full attack'},
    },
    # Data Exfiltration
    'data_exfil': {
        1: {'bursts': 3,  'burst_size': 2,  'delay': 1.0, 'label': '6 connections  — low & slow'},
        2: {'bursts': 8,  'burst_size': 5,  'delay': 0.3, 'label': '40 connections — moderate'},
        3: {'bursts': 20, 'burst_size': 15, 'delay': 0.05,'label': '300 connections — full exfil'},
    },
    # C2 Beacon
    'c2_beacon': {
        1: {'beacons': 3,  'interval': 8.0,  'label': '3 beacons  — slow interval (8s)'},
        2: {'beacons': 8,  'interval': 3.0,  'label': '8 beacons  — medium interval (3s)'},
        3: {'beacons': 20, 'interval': 0.5,  'label': '20 beacons — fast beacon (0.5s)'},
    },
}


# ══════════════════════════════════════════════════════════════
# 1. PORT SCAN
# ══════════════════════════════════════════════════════════════

def run_port_scan(target, agg):
    cfg = AGGRESSIVENESS['port_scan'][agg]
    banner(f"PORT SCAN  [{AGG_LABELS[agg]}]", RED if agg == 3 else YEL if agg == 2 else GRN)
    step(f"Target     : {target}")
    step(f"Ports      : {len(cfg['ports'])}  ({cfg['label']})")
    step(f"Delay/port : {cfg['delay']}s")
    print()

    open_ports  = []
    closed_ports = 0
    start = time.time()

    lock = threading.Lock()

    def scan(port):
        nonlocal closed_ports
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            r = s.connect_ex((target, port))
            s.close()
            with lock:
                if r == 0:
                    open_ports.append(port)
                    print(f"  {GRN}  OPEN   {port}{RST}")
                else:
                    closed_ports += 1
                    if closed_ports % 20 == 0:
                        print(f"  {CYN}  scanned {len(open_ports) + closed_ports}/{len(cfg['ports'])} ports...{RST}")
        except Exception:
            pass

    threads = []
    for port in cfg['ports']:
        t = threading.Thread(target=scan, args=(port,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(cfg['delay'])

    for t in threads:
        t.join(timeout=2)

    elapsed = time.time() - start
    done(f"Port scan complete in {elapsed:.1f}s")
    step(f"Open ports    : {open_ports or 'none'}")
    step(f"Ports scanned : {len(cfg['ports'])}")
    if agg >= 2:
        warn("Detection expected — check Dashboard > Alerts")
    else:
        warn("Below threshold — no alert expected (baseline test)")


# ══════════════════════════════════════════════════════════════
# 2. BRUTE FORCE
# ══════════════════════════════════════════════════════════════

USERNAMES = ['admin', 'root', 'user', 'test', 'guest', 'administrator', 'pi', 'ubuntu']
PASSWORDS = ['admin', 'password', '123456', 'root', 'test', 'guest', 'letmein', 'changeme', 'qwerty', '111111']

def run_brute_force(target, agg, port=22):
    cfg = AGGRESSIVENESS['brute_force'][agg]
    banner(f"BRUTE FORCE  [{AGG_LABELS[agg]}]  port {port}", RED if agg == 3 else YEL if agg == 2 else GRN)
    step(f"Target     : {target}:{port}")
    step(f"Attempts   : {cfg['attempts']}  ({cfg['label']})")
    step(f"Delay      : {cfg['delay']}s between attempts")
    print()

    pairs = [(u, p) for u in USERNAMES for p in PASSWORDS]
    random.shuffle(pairs)

    success = 0
    for i, (user, pw) in enumerate(pairs[:cfg['attempts']]):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((target, port))
            s.send(f"USER {user}\r\n".encode())
            time.sleep(0.05)
            s.send(f"PASS {pw}\r\n".encode())
            s.close()
            success += 1
            if (i + 1) % 10 == 0 or i == 0:
                print(f"  {CYN}  attempt {i+1:3d}/{cfg['attempts']}  {user}:{pw}{RST}")
        except Exception:
            if (i + 1) % 10 == 0:
                print(f"  {YEL}  attempt {i+1:3d}/{cfg['attempts']}  (port closed){RST}")
        time.sleep(cfg['delay'])

    done(f"Brute force complete — {success}/{cfg['attempts']} connections reached port")
    if agg >= 2:
        warn("Detection expected — check Dashboard > Alerts")
    else:
        warn("Below threshold — no alert expected")


# ══════════════════════════════════════════════════════════════
# 3. SYN FLOOD / DoS
# ══════════════════════════════════════════════════════════════

def run_syn_flood(target, agg, port=80):
    cfg = AGGRESSIVENESS['syn_flood'][agg]
    total = cfg['threads'] * cfg['pkts_per_thread']
    banner(f"SYN FLOOD / DoS  [{AGG_LABELS[agg]}]  port {port}", RED if agg == 3 else YEL if agg == 2 else GRN)
    step(f"Target     : {target}:{port}")
    step(f"Packets    : {total}  ({cfg['label']})")
    step(f"Threads    : {cfg['threads']}")
    print()

    sent_total = [0]
    lock = threading.Lock()

    def flood(n):
        for _ in range(n):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((target, port))
                s.close()
                with lock:
                    sent_total[0] += 1
                    if sent_total[0] % 50 == 0:
                        print(f"  {CYN}  {sent_total[0]}/{total} packets sent...{RST}")
            except Exception:
                with lock:
                    sent_total[0] += 1
            time.sleep(cfg['delay'])

    start = time.time()
    threads = []
    for _ in range(cfg['threads']):
        t = threading.Thread(target=flood, args=(cfg['pkts_per_thread'],), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=30)

    elapsed = time.time() - start
    done(f"Flood complete — {sent_total[0]} packets in {elapsed:.1f}s  ({sent_total[0]/elapsed:.0f} pps)")
    if agg >= 2:
        warn("Detection expected — check Dashboard > Alerts")
    else:
        warn("Below threshold — no alert expected")


# ══════════════════════════════════════════════════════════════
# 4. RANSOMWARE (safe file-based simulation)
# ══════════════════════════════════════════════════════════════

def _rand_key():
    return bytes(random.randint(0, 255) for _ in range(32))

def _xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _pe_header(ransomware=True):
    mz   = b'MZ'
    pe   = b'PE\x00\x00'
    mach = struct.pack('<H', random.choice([0x014c, 0x8664]))
    secs = struct.pack('<H', random.randint(5, 9) if ransomware else random.randint(2, 4))
    dll  = struct.pack('<H', 0x0002 if ransomware else 0x8540)
    stk  = struct.pack('<I', random.choice([131072, 524288]))
    mark = b'RANSOM_CRYPT_KEY_' if ransomware else b'NORMAL_SYSTEM_LIB'
    return mz + b'\x00'*58 + pe + mach + secs + b'\x00'*12 + dll + stk + b'\x00'*16 + mark

def _rand_name(base, ext):
    sfx = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{base}_{sfx}{ext}"

def _ransom_note():
    btc  = '1' + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=30))
    hrs  = random.choice([24, 48, 72])
    amt  = round(random.uniform(0.1, 2.5), 2)
    uid  = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    return f"""!!! YOUR FILES ARE ENCRYPTED !!!

ID      : {uid}
Ransom  : {amt} BTC
Address : {btc}
Deadline: {hrs} hours

[THIS IS A SIMULATION — NOT REAL RANSOMWARE]
"""

FILE_TEMPLATES = [
    ('ransomware_payload', '.dll',  True),
    ('crypto_locker',      '.dll',  True),
    ('wiper_engine',       '.dll',  True),
    ('keylogger',          '.dll',  True),
    ('dropper_stage2',     '.exe',  True),
    ('ransom_engine',      '.exe',  True),
    ('c2_client',          '.dll',  True),
    ('persistence_hook',   '.dll',  True),
    ('screen_capture',     '.exe',  True),
    ('exfil_agent',        '.dll',  True),
]

def run_ransomware(target, agg):
    cfg = AGGRESSIVENESS['ransomware'][agg]
    banner(f"RANSOMWARE SIMULATION  [{AGG_LABELS[agg]}]  (file-based, safe)", RED if agg == 3 else YEL if agg == 2 else GRN)
    step(f"Watched dir : {WATCHED_DIR}")
    step(f"Files       : {cfg['file_count']}  ({cfg['label']})")
    step(f"Delay       : {cfg['delay']}s between drops")
    print()

    key = _rand_key()
    picks = random.sample(FILE_TEMPLATES, min(cfg['file_count'], len(FILE_TEMPLATES)))

    for base, ext, is_ransom in picks:
        fname   = _rand_name(base, ext)
        content = (f"{base} malicious content BTC_RANSOM_PAYLOAD ".encode()) * random.randint(30, 80)
        enc     = _xor(content, key)
        final   = _pe_header(ransomware=True) + enc
        path    = os.path.join(WATCHED_DIR, fname)
        with open(path, 'wb') as f:
            f.write(final)
        print(f"  {RED}  🔴 Dropped : {fname}{RST}")
        time.sleep(cfg['delay'])

    # Drop ransom note
    note_path = os.path.join(WATCHED_DIR, 'READ_ME_NOW.txt')
    with open(note_path, 'w') as f:
        f.write(_ransom_note())
    print(f"  {RED}  📝 Dropped : READ_ME_NOW.txt{RST}")

    done(f"Ransomware simulation complete — {cfg['file_count']} payloads dropped")
    warn("File monitor should auto-quarantine — check Dashboard > Alerts")


# ══════════════════════════════════════════════════════════════
# 5. MIXED / APT KILL CHAIN
# ══════════════════════════════════════════════════════════════

def run_mixed_apt(target, agg):
    banner(f"MIXED / APT KILL CHAIN  [{AGG_LABELS[agg]}]", RED if agg == 3 else YEL if agg == 2 else GRN)
    step("Full attack chain: Recon → Brute Force → Ransomware")
    step(f"Target : {target}")
    print()

    # Stage 1 — Recon (port scan)
    print(f"  {CYN}── Stage 1: RECONNAISSANCE (port scan){RST}")
    run_port_scan(target, min(agg, 3))
    time.sleep(2)

    # Stage 2 — Brute Force
    print(f"\n  {CYN}── Stage 2: CREDENTIAL ATTACK (brute force){RST}")
    run_brute_force(target, agg)
    time.sleep(2)

    # Stage 3 — Ransomware payload
    print(f"\n  {CYN}── Stage 3: RANSOMWARE PAYLOAD{RST}")
    run_ransomware(target, agg)

    done("APT Kill Chain simulation complete")
    warn("Check Dashboard for correlated incident across all 3 stages")


# ══════════════════════════════════════════════════════════════
# 6. DATA EXFILTRATION
# ══════════════════════════════════════════════════════════════

def run_data_exfil(target, agg):
    cfg = AGGRESSIVENESS['data_exfil'][agg]
    total = cfg['bursts'] * cfg['burst_size']
    banner(f"DATA EXFILTRATION  [{AGG_LABELS[agg]}]", RED if agg == 3 else YEL if agg == 2 else GRN)
    step(f"Target      : {target}")
    step(f"Connections : {total}  ({cfg['label']})")
    print()

    sent = 0
    for burst in range(cfg['bursts']):
        print(f"  {CYN}  Burst {burst+1}/{cfg['bursts']} — sending {cfg['burst_size']} connections...{RST}")
        for _ in range(cfg['burst_size']):
            port = random.choice([80, 443, 8080, 9000, 4444, 1337, 6666])
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex((target, port))
                # Send a payload blob simulating exfiltration
                payload = b'EXFIL:' + os.urandom(random.randint(512, 4096))
                try:
                    s.sendall(payload)
                except Exception:
                    pass
                s.close()
                sent += 1
            except Exception:
                sent += 1
        time.sleep(cfg['delay'])

    done(f"Data exfiltration complete — {sent} connection attempts")
    if agg >= 2:
        warn("Detection expected (C2/exfil pattern) — check Dashboard > Alerts")
    else:
        warn("Low aggressiveness — may not trigger alert")


# ══════════════════════════════════════════════════════════════
# 7. C2 BEACON
# ══════════════════════════════════════════════════════════════

def run_c2_beacon(target, agg):
    cfg = AGGRESSIVENESS['c2_beacon'][agg]
    banner(f"C2 BEACON  [{AGG_LABELS[agg]}]", RED if agg == 3 else YEL if agg == 2 else GRN)
    step(f"Target   : {target}")
    step(f"Beacons  : {cfg['beacons']}  ({cfg['label']})")
    step(f"Interval : {cfg['interval']}s")
    print()

    c2_ports = [4444, 1337, 8888, 9999, 6666, 7777, 31337]

    for i in range(cfg['beacons']):
        port = random.choice(c2_ports)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect_ex((target, port))
            # Beacon payload
            beacon = f"BEACON|{i+1}|{datetime.utcnow().isoformat()}|SYSTEM_INFO|HOSTNAME".encode()
            try:
                s.sendall(beacon)
            except Exception:
                pass
            s.close()
        except Exception:
            pass

        ts = datetime.now().strftime('%H:%M:%S')
        print(f"  {CYN}  [{ts}] Beacon {i+1:3d}/{cfg['beacons']}  → {target}:{port}{RST}")
        time.sleep(cfg['interval'])

    done(f"C2 beacon complete — {cfg['beacons']} beacons sent")
    if agg >= 2:
        warn("Detection expected (periodic callback pattern) — check Dashboard > Alerts")
    else:
        warn("Low aggressiveness — may not trigger alert")


# ══════════════════════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════════════════════

ATTACKS = {
    '1': ('Port Scan',          run_port_scan,   True),
    '2': ('Brute Force',        run_brute_force, True),
    '3': ('SYN Flood / DoS',    run_syn_flood,   True),
    '4': ('Ransomware (file)',   run_ransomware,  False),
    '5': ('Mixed / APT Chain',  run_mixed_apt,   True),
    '6': ('Data Exfiltration',  run_data_exfil,  True),
    '7': ('C2 Beacon',          run_c2_beacon,   True),
}

def pick_aggressiveness():
    print(f"\n  {BLD}Aggressiveness:{RST}")
    print(f"  {GRN}1{RST}  Low    — stays below detection threshold (baseline test)")
    print(f"  {YEL}2{RST}  Medium — crosses thresholds, generates alerts")
    print(f"  {RED}3{RST}  High   — full intensity, guaranteed detection")
    while True:
        a = input("\n  Choose aggressiveness [1/2/3]: ").strip()
        if a in ('1', '2', '3'):
            return int(a)
        print("  Invalid — enter 1, 2, or 3")

def pick_target():
    t = input(f"\n  Target IP [{TARGET_IP}]: ").strip()
    return t if t else TARGET_IP

def show_menu():
    print(f"\n{CYN}{BLD}{'═'*62}{RST}")
    print(f"{CYN}{BLD}   CyberDefense AI — Unified Attack Simulator{RST}")
    print(f"{CYN}{BLD}{'═'*62}{RST}")
    print()
    for k, (name, _, network) in ATTACKS.items():
        tag = f"  {CYN}[network]{RST}" if network else f"  {YEL}[file]  {RST}"
        print(f"  {BLD}{k}{RST}  {name:<25}{tag}")
    print()
    print(f"  {BLD}8{RST}  Run ALL attacks sequentially")
    print(f"  {BLD}9{RST}  Clean watched/ folder")
    print(f"  {BLD}0{RST}  Exit")
    print()

def clean_watched():
    files = [f for f in os.listdir(WATCHED_DIR)]
    if not files:
        print(f"\n  {GRN}Watched folder already empty{RST}\n")
        return
    for f in files:
        try:
            os.remove(os.path.join(WATCHED_DIR, f))
            print(f"  {YEL}Removed: {f}{RST}")
        except Exception as e:
            print(f"  {RED}Could not remove {f}: {e}{RST}")
    done(f"Cleaned {len(files)} files from watched/")


if __name__ == '__main__':
    # Command-line quick-run: python attack_simulator.py <attack_num> <agg_level> [target_ip]
    if len(sys.argv) >= 3:
        atk = sys.argv[1]
        agg = int(sys.argv[2])
        tgt = sys.argv[3] if len(sys.argv) > 3 else TARGET_IP
        if atk in ATTACKS:
            name, fn, _ = ATTACKS[atk]
            print(f"\n{CYN}Running {name} at aggressiveness {agg} against {tgt}...{RST}\n")
            fn(tgt, agg)
        elif atk == '9':
            clean_watched()
        sys.exit(0)

    # Interactive menu
    while True:
        show_menu()
        choice = input("  Select attack [0-9]: ").strip()

        if choice == '0':
            print(f"\n  {GRN}Exiting simulator.{RST}\n")
            break

        elif choice == '9':
            clean_watched()

        elif choice == '8':
            target = pick_target()
            agg    = pick_aggressiveness()
            print(f"\n{RED}{BLD}Running ALL attacks at {AGG_LABELS[agg]} aggressiveness against {target}{RST}\n")
            for k in sorted(ATTACKS.keys()):
                name, fn, _ = ATTACKS[k]
                print(f"\n{CYN}{BLD}{'─'*50}{RST}")
                print(f"{CYN}  → {name}{RST}")
                print(f"{CYN}{'─'*50}{RST}")
                fn(target, agg)
                time.sleep(3)
            done("All attacks complete — check Dashboard for correlated incidents")

        elif choice in ATTACKS:
            name, fn, needs_target = ATTACKS[choice]
            target = pick_target() if needs_target else TARGET_IP
            agg    = pick_aggressiveness()
            fn(target, agg)

        else:
            print(f"\n  {RED}Invalid choice — enter 0-9{RST}")
            continue

        input(f"\n  {CYN}Press Enter to return to menu...{RST}")

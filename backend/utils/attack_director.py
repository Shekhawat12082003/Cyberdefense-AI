"""
Attack Director — Safe Simulation Engine for CyberDefense-AI
Generates controlled, representative telemetry for the SOC demo.
All simulations are contained within the lab environment.
No real malware, no real encryption, no real network attacks.
All simulations run through the existing detection pipeline.
"""
import os
import json
import uuid
import time
import random
import struct
import string
import hashlib
import threading
import socket
import platform
from datetime import datetime
from typing import Optional

# Import existing modules
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

LAB_DIR      = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'lab')
WATCHED_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'watched')
HONEYPOT_DIR = os.path.join(LAB_DIR, 'honeypot')

# Simulation state
_active_scenario: Optional[str] = None
_scenario_status: dict = {}
_output_callbacks: list = []
_event_callbacks:  list = []

_lock = threading.Lock()


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _get_local_ip() -> str:
    """Get the local machine's IP address — actually observed, not fabricated."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _get_current_pid() -> int:
    return os.getpid()


def _rand_ip() -> str:
    """Generate a fake RFC 1918 source IP for simulation."""
    return f'192.168.{random.randint(1,5)}.{random.randint(10,250)}'


def _rand_port() -> int:
    return random.randint(49152, 65535)


def _rand_suffix(n: int = 6) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _rand_key() -> bytes:
    return bytes(random.randint(0, 255) for _ in range(random.randint(16, 32)))


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _add_pe_header(data: bytes, ransomware: bool = True) -> bytes:
    """Add a synthetic PE-like header for file monitor scanning."""
    mz        = b'MZ'
    pe        = b'PE\x00\x00'
    machine   = struct.pack('<H', 0x014c)
    sections  = struct.pack('<H', random.randint(5, 9) if ransomware else random.randint(2, 4))
    dll_chars = struct.pack('<H', 0x0000 if ransomware else 0x8540)
    stack     = struct.pack('<I', random.choice([131072, 262144]) if ransomware else 1048576)
    marker    = (b'1BTC_SIM_RANSOM_DEMO_' if ransomware else b'NORMAL_APP_FILE______')
    header    = mz + b'\x00' * 58 + pe + machine + sections + b'\x00' * 12 + dll_chars + stack + b'\x00' * 16 + marker
    return header + data


def _log(msg: str, scenario_id: str = None):
    """Emit a log line to all registered output callbacks."""
    entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'message':   msg,
        'scenario_id': scenario_id,
    }
    for cb in _output_callbacks:
        try:
            cb(entry)
        except Exception:
            pass
    print(f"[LAB] {msg}")


def _emit_event(event: dict):
    """Emit a security event to all registered callbacks."""
    for cb in _event_callbacks:
        try:
            cb(event)
        except Exception:
            pass


def register_output_callback(fn):
    _output_callbacks.append(fn)


def register_event_callback(fn):
    _event_callbacks.append(fn)


def get_active_scenario() -> Optional[str]:
    with _lock:
        return _active_scenario


def get_scenario_status(scenario_id: str = None) -> dict:
    with _lock:
        if scenario_id:
            return _scenario_status.get(scenario_id, {})
        return dict(_scenario_status)


def _start_scenario(name: str) -> str:
    global _active_scenario
    scenario_id = f'{name}_{_rand_suffix(8)}'
    with _lock:
        _active_scenario = scenario_id
        _scenario_status[scenario_id] = {
            'name':       name,
            'status':     'RUNNING',
            'started_at': datetime.utcnow().isoformat(),
            'steps':      [],
        }
    return scenario_id


def _end_scenario(scenario_id: str, status: str = 'COMPLETED'):
    global _active_scenario
    with _lock:
        if scenario_id in _scenario_status:
            _scenario_status[scenario_id]['status'] = status
            _scenario_status[scenario_id]['ended_at'] = datetime.utcnow().isoformat()
        _active_scenario = None


def _add_step(scenario_id: str, step: str):
    with _lock:
        if scenario_id in _scenario_status:
            _scenario_status[scenario_id]['steps'].append({
                'time': datetime.utcnow().isoformat(),
                'step': step,
            })


# ─────────────────────────────────────────────────────────
# Event builders
# ─────────────────────────────────────────────────────────

def _build_event(
    event_type:   str,
    severity:     str,
    scenario_id:  str,
    source_ip:    str    = None,
    source_port:  int    = None,
    dest_ip:      str    = None,
    dest_port:    int    = None,
    protocol:     str    = None,
    process_name: str    = None,
    process_pid:  int    = None,
    attack_type:  str    = None,
    attack_mitre: str    = None,
    honeypot_triggered: bool = False,
    honeypot_resource:  str  = None,
    file_name:    str    = None,
    description:  str    = None,
    **extras,
) -> dict:
    from utils.event_schema import create_event
    local_ip = _get_local_ip()
    return create_event(
        event_type=event_type,
        severity=severity,
        scenario_id=scenario_id,
        source_ip=source_ip or _rand_ip(),
        source_port=source_port or _rand_port(),
        dest_ip=dest_ip or local_ip,
        dest_port=dest_port,
        source_protocol=protocol,
        process_name=process_name,
        process_pid=process_pid or _get_current_pid(),
        file_name=file_name,
        attack_type=attack_type,
        attack_mitre=attack_mitre,
        honeypot_triggered=honeypot_triggered,
        honeypot_resource=honeypot_resource,
        description=description or event_type,
        raw=extras,
    )


# ─────────────────────────────────────────────────────────
# Individual Simulations
# ─────────────────────────────────────────────────────────

def simulate_ransomware(scenario_id: str = None) -> str:
    """
    Simulates a ransomware attack by dropping synthetic PE files into watched/.
    Uses the existing file monitor + ML pipeline for detection.
    No real encryption of user files.
    """
    sid = scenario_id or _start_scenario('ransomware')
    _log('🦠 Starting ransomware simulation...', sid)
    _add_step(sid, 'RANSOMWARE_START')

    def _run():
        try:
            os.makedirs(WATCHED_DIR, exist_ok=True)
            src_ip = _rand_ip()
            key    = _rand_key()

            files_created = []

            # Stage 1: Drop dropper
            _log('  Phase 1: Dropper deployment', sid)
            dropper_name = f'dropper_stage1_{_rand_suffix()}.exe'
            dropper_content = b'DROPPER_PAYLOAD_SIM ' + (b'X' * random.randint(100, 300))
            dropper_data = _add_pe_header(_xor_encrypt(dropper_content, key), ransomware=True)
            dropper_path = os.path.join(WATCHED_DIR, dropper_name)
            with open(dropper_path, 'wb') as f:
                f.write(dropper_data)
            files_created.append(dropper_path)

            evt = _build_event(
                'FILE_RANSOMWARE_DROPPER', 'HIGH', sid,
                source_ip=src_ip, process_name='dropper_stage1.exe',
                attack_type='RANSOMWARE', attack_mitre='T1486',
                file_name=dropper_name,
                description=f'Ransomware dropper deployed: {dropper_name}',
            )
            _emit_event(evt)
            time.sleep(1.5)

            # Stage 2: Main payload files
            _log('  Phase 2: Encryption engine', sid)
            payloads = ['ransomware_payload', 'crypto_locker', 'wiper_engine']
            for base in random.sample(payloads, 2):
                fname = f'{base}_{_rand_suffix()}.dll'
                content = b'RANSOM_ENC_ENGINE_SIM ' + (b'E' * random.randint(200, 500))
                data = _add_pe_header(_xor_encrypt(content, key), ransomware=True)
                path = os.path.join(WATCHED_DIR, fname)
                with open(path, 'wb') as f:
                    f.write(data)
                files_created.append(path)
                evt = _build_event(
                    'FILE_RANSOMWARE_PAYLOAD', 'CRITICAL', sid,
                    source_ip=src_ip, process_name=fname,
                    attack_type='RANSOMWARE', attack_mitre='T1486',
                    file_name=fname,
                    description=f'Ransomware payload: {fname}',
                )
                _emit_event(evt)
                time.sleep(1.2)

            # Stage 3: Honeypot access simulation
            _log('  Phase 3: Honeypot interaction', sid)
            _simulate_honeypot_access(sid, src_ip, 'ransomware_payload.exe')

            # Stage 4: Ransom note
            _log('  Phase 4: Ransom note', sid)
            note_name = 'READ_ME_NOW.txt'
            note_path = os.path.join(WATCHED_DIR, note_name)
            note_content = (
                f'[SIMULATION - NOT REAL RANSOMWARE]\n'
                f'Scenario ID: {sid}\n'
                f'YOUR FILES ARE ENCRYPTED - SIMULATION ONLY\n'
                f'BTC: 1FAKESIMULATEDDEMOADDRESS{_rand_suffix(10)}\n'
                f'Amount: {round(random.uniform(0.1, 2.0), 2)} BTC\n'
            )
            with open(note_path, 'w') as f:
                f.write(note_content)

            evt = _build_event(
                'FILE_RANSOM_NOTE', 'CRITICAL', sid,
                source_ip=src_ip, attack_type='RANSOMWARE',
                file_name=note_name,
                description='Ransom note dropped',
            )
            _emit_event(evt)

            _log(f'✅ Ransomware simulation complete ({len(files_created)} files)', sid)
            _add_step(sid, 'RANSOMWARE_COMPLETE')

        except Exception as e:
            _log(f'❌ Ransomware simulation error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_portscan(scenario_id: str = None) -> str:
    """
    Simulates a port scan by emitting events that look like port scan telemetry.
    Does NOT actually scan any ports.
    """
    sid = scenario_id or _start_scenario('portscan')
    _log('🔍 Starting port scan simulation...', sid)
    _add_step(sid, 'PORTSCAN_START')

    def _run():
        try:
            src_ip    = _rand_ip()
            local_ip  = _get_local_ip()
            ports     = random.sample(range(20, 10000), random.randint(15, 40))

            _log(f'  Simulated scanner: {src_ip} → {local_ip}', sid)
            _log(f'  Ports probed: {len(ports)}', sid)

            for port in ports:
                evt = _build_event(
                    'NETWORK_PORT_SCAN', 'HIGH', sid,
                    source_ip=src_ip, source_port=_rand_port(),
                    dest_ip=local_ip, dest_port=port,
                    protocol='TCP',
                    attack_type='PORT_SCAN', attack_mitre='T1046',
                    description=f'Port scan: {src_ip}:{_rand_port()} → {local_ip}:{port}',
                )
                _emit_event(evt)
                time.sleep(0.08)

            # Emit a consolidated alert
            alert = {
                'timestamp':   datetime.utcnow().isoformat(),
                'type':        'PORT_SCAN',
                'ip':          src_ip,
                'severity':    'HIGH',
                'description': f'Port scan from {src_ip}: {len(ports)} ports in 5s',
                'ports_hit':   sorted(ports)[:20],
                'scenario_id': sid,
            }
            _emit_event({'_network_alert': alert, 'scenario_id': sid})

            _log(f'✅ Port scan simulation complete', sid)
            _add_step(sid, 'PORTSCAN_COMPLETE')

        except Exception as e:
            _log(f'❌ Port scan error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_bruteforce(scenario_id: str = None) -> str:
    """Simulates brute force authentication attempts — no real login attempts."""
    sid = scenario_id or _start_scenario('brute_force')
    _log('🔑 Starting brute force simulation...', sid)
    _add_step(sid, 'BRUTEFORCE_START')

    def _run():
        try:
            src_ip   = _rand_ip()
            local_ip = _get_local_ip()
            port     = random.choice([22, 3389, 5900])
            attempts = random.randint(20, 50)
            service  = {22: 'SSH', 3389: 'RDP', 5900: 'VNC'}[port]

            _log(f'  Brute force {service} on port {port}', sid)
            _log(f'  Attacker: {src_ip}, Attempts: {attempts}', sid)

            for i in range(min(attempts, 10)):
                evt = _build_event(
                    'NETWORK_BRUTE_FORCE', 'HIGH', sid,
                    source_ip=src_ip, source_port=_rand_port(),
                    dest_ip=local_ip, dest_port=port,
                    protocol='TCP',
                    attack_type='BRUTE_FORCE', attack_mitre='T1110',
                    description=f'Brute force attempt {i+1}/{attempts} on {service}:{port}',
                )
                _emit_event(evt)
                time.sleep(0.15)

            alert = {
                'timestamp':        datetime.utcnow().isoformat(),
                'type':             'BRUTE_FORCE',
                'ip':               src_ip,
                'severity':         'HIGH',
                'description':      f'Brute force on {service}:{port} from {src_ip}: {attempts} attempts',
                'target_port':      port,
                'connection_count': attempts,
                'scenario_id':      sid,
            }
            _emit_event({'_network_alert': alert, 'scenario_id': sid})

            _log(f'✅ Brute force simulation complete', sid)
            _add_step(sid, 'BRUTEFORCE_COMPLETE')

        except Exception as e:
            _log(f'❌ Brute force error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_phishing(scenario_id: str = None) -> str:
    """Simulates a phishing campaign — generates telemetry events only."""
    sid = scenario_id or _start_scenario('phishing')
    _log('🎣 Starting phishing simulation...', sid)
    _add_step(sid, 'PHISHING_START')

    def _run():
        try:
            src_ip   = _rand_ip()
            pid      = _get_current_pid()

            # Stage 1: Suspicious email attachment process
            _log('  Stage 1: Phishing email detected', sid)
            evt = _build_event(
                'PHISHING_EMAIL_ATTACHMENT', 'HIGH', sid,
                source_ip=src_ip,
                process_name='OUTLOOK.EXE',
                process_pid=pid,
                attack_type='PHISHING', attack_mitre='T1566.001',
                description='Suspicious email attachment opened',
            )
            _emit_event(evt)
            time.sleep(1)

            # Stage 2: Payload execution
            _log('  Stage 2: Payload process spawned', sid)
            payload_name = f'invoice_{_rand_suffix()}.exe'
            os.makedirs(WATCHED_DIR, exist_ok=True)
            payload_path = os.path.join(WATCHED_DIR, payload_name)
            content = b'PHISHING_PAYLOAD_SIM ' + (b'P' * 200)
            with open(payload_path, 'wb') as f:
                f.write(_add_pe_header(content, ransomware=False))

            evt = _build_event(
                'PHISHING_PAYLOAD_EXEC', 'CRITICAL', sid,
                source_ip=src_ip,
                process_name=payload_name,
                process_pid=pid + 1,
                attack_type='PHISHING', attack_mitre='T1204.002',
                file_name=payload_name,
                description=f'Phishing payload executed: {payload_name}',
            )
            _emit_event(evt)
            time.sleep(1)

            # Stage 3: C2 connection
            _log('  Stage 3: C2 beacon attempt', sid)
            c2_ip = _rand_ip()
            for _ in range(5):
                evt = _build_event(
                    'PHISHING_C2_BEACON', 'CRITICAL', sid,
                    source_ip=c2_ip, source_port=_rand_port(),
                    dest_ip=_get_local_ip(), dest_port=443,
                    protocol='HTTPS',
                    attack_type='C2_BEACON', attack_mitre='T1071.001',
                    description=f'C2 beacon: {c2_ip} → {_get_local_ip()}:443',
                )
                _emit_event(evt)
                time.sleep(0.5)

            _log('✅ Phishing simulation complete', sid)
            _add_step(sid, 'PHISHING_COMPLETE')

        except Exception as e:
            _log(f'❌ Phishing error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_suspicious_process(scenario_id: str = None) -> str:
    """Simulates suspicious process activity using real current process info."""
    sid = scenario_id or _start_scenario('suspicious_process')
    _log('⚙️  Starting suspicious process simulation...', sid)
    _add_step(sid, 'PROCESS_START')

    def _run():
        try:
            pid      = _get_current_pid()
            src_ip   = _rand_ip()
            proc_name = f'suspicious_tool_{_rand_suffix()}.exe'

            _log(f'  Simulated malicious process: {proc_name} (PID {pid})', sid)

            parent_pid  = os.getppid() if hasattr(os, 'getppid') else 0
            parent_name = 'python.exe'

            if PSUTIL_AVAILABLE:
                try:
                    proc = psutil.Process(pid)
                    cpu  = proc.cpu_percent(interval=0.1)
                    mem  = proc.memory_info().rss // 1024 // 1024
                    parent_pid = proc.ppid()
                    try:
                        parent_name = psutil.Process(parent_pid).name()
                    except Exception:
                        pass
                except Exception:
                    cpu, mem = 0.0, 0

            evt = _build_event(
                'SUSPICIOUS_PROCESS', 'HIGH', sid,
                source_ip=src_ip,
                process_name=proc_name,
                process_pid=pid,
                process_parent_pid=parent_pid,
                process_parent_name=parent_name,
                attack_type='SUSPICIOUS_PROCESS', attack_mitre='T1059',
                description=f'Suspicious process: {proc_name} PID={pid}',
            )
            _emit_event(evt)
            time.sleep(1)

            # Simulate honeypot access by suspicious process
            _log('  Process accessing honeypot resources...', sid)
            _simulate_honeypot_access(sid, src_ip, proc_name)

            # Drop suspicious file
            _log('  Process dropping suspicious payload...', sid)
            os.makedirs(WATCHED_DIR, exist_ok=True)
            fname = f'susp_{_rand_suffix()}.dll'
            content = b'HEUR_SUSP_PACKED:' + (b'S' * 200)
            with open(os.path.join(WATCHED_DIR, fname), 'wb') as f:
                f.write(_add_pe_header(content, ransomware=False))

            _log('✅ Suspicious process simulation complete', sid)
            _add_step(sid, 'PROCESS_COMPLETE')

        except Exception as e:
            _log(f'❌ Suspicious process error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_data_exfiltration(scenario_id: str = None) -> str:
    """Simulates data exfiltration — telemetry events only."""
    sid = scenario_id or _start_scenario('data_exfil')
    _log('📤 Starting data exfiltration simulation...', sid)
    _add_step(sid, 'EXFIL_START')

    def _run():
        try:
            src_ip   = _rand_ip()
            local_ip = _get_local_ip()
            mb_sim   = round(random.uniform(50, 200), 1)

            _log(f'  Simulated exfil target: {src_ip}', sid)
            _log(f'  Simulated data volume: {mb_sim} MB', sid)

            # Access honeypot data first
            _log('  Accessing sensitive honeypot files...', sid)
            _simulate_honeypot_access(sid, src_ip, 'data_stealer.exe')
            time.sleep(0.5)

            # Exfil event
            evt = _build_event(
                'DATA_EXFILTRATION', 'CRITICAL', sid,
                source_ip=src_ip, source_port=_rand_port(),
                dest_ip=local_ip, dest_port=443,
                protocol='HTTPS',
                attack_type='DATA_EXFIL', attack_mitre='T1041',
                description=f'Data exfiltration: {mb_sim} MB to {src_ip}',
            )
            evt['_exfil_mb'] = mb_sim
            _emit_event(evt)

            alert = {
                'timestamp':   datetime.utcnow().isoformat(),
                'type':        'DATA_EXFIL',
                'ip':          local_ip,
                'severity':    'CRITICAL',
                'description': f'Possible data exfiltration: {mb_sim} MB outbound',
                'bytes_sent':  int(mb_sim * 1024 * 1024),
                'scenario_id': sid,
            }
            _emit_event({'_network_alert': alert, 'scenario_id': sid})

            _log('✅ Data exfiltration simulation complete', sid)
            _add_step(sid, 'EXFIL_COMPLETE')

        except Exception as e:
            _log(f'❌ Exfil error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_honeypot_access(scenario_id: str = None) -> str:
    """Directly triggers honeypot interactions."""
    sid = scenario_id or _start_scenario('honeypot')
    _log('🍯 Starting honeypot simulation...', sid)
    _add_step(sid, 'HONEYPOT_START')

    def _run():
        try:
            src_ip   = _rand_ip()
            proc     = f'recon_tool_{_rand_suffix()}.exe'

            _log(f'  Simulated attacker: {src_ip}', sid)
            _log(f'  Process: {proc}', sid)

            _simulate_honeypot_access(sid, src_ip, proc, count=random.randint(2, 5))

            _log('✅ Honeypot simulation complete', sid)
            _add_step(sid, 'HONEYPOT_COMPLETE')

        except Exception as e:
            _log(f'❌ Honeypot error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


def simulate_full_attack(scenario_id: str = None) -> str:
    """
    Multi-stage full attack simulation.
    Runs all stages in sequence through the real detection pipeline.
    Each stage generates events that feed the correlation engine.
    """
    sid = scenario_id or _start_scenario('full_attack')
    _log('🚀 === FULL ATTACK SIMULATION ===', sid)
    _log(f'    Scenario ID: {sid}', sid)
    _add_step(sid, 'FULL_ATTACK_START')

    def _run():
        try:
            src_ip   = _rand_ip()
            local_ip = _get_local_ip()
            pid      = _get_current_pid()

            # ── Stage 1: Recon ───────────────────────────────
            _log('\n  STAGE 1: Reconnaissance', sid)
            _add_step(sid, 'STAGE_1_RECON')
            ports = random.sample(range(20, 5000), random.randint(15, 25))
            for port in ports[:5]:
                evt = _build_event(
                    'NETWORK_PORT_SCAN', 'HIGH', sid,
                    source_ip=src_ip, dest_ip=local_ip,
                    dest_port=port, protocol='TCP',
                    attack_type='PORT_SCAN', attack_mitre='T1046',
                    description=f'Recon port scan: {src_ip} → {local_ip}:{port}',
                )
                _emit_event(evt)
                time.sleep(0.3)
            _log(f'     Port scan: {len(ports)} ports probed', sid)
            time.sleep(1)

            # ── Stage 2: Suspicious Activity ─────────────────
            _log('\n  STAGE 2: Suspicious Activity', sid)
            _add_step(sid, 'STAGE_2_SUSPICIOUS')
            brute_port = random.choice([22, 3389, 5900])
            for i in range(5):
                evt = _build_event(
                    'NETWORK_BRUTE_FORCE', 'HIGH', sid,
                    source_ip=src_ip, dest_ip=local_ip,
                    dest_port=brute_port, protocol='TCP',
                    attack_type='BRUTE_FORCE', attack_mitre='T1110',
                    description=f'Auth brute force attempt {i+1} on port {brute_port}',
                )
                _emit_event(evt)
                time.sleep(0.2)
            _log(f'     Brute force: 5 attempts on port {brute_port}', sid)
            time.sleep(1)

            # ── Stage 3: Suspicious Process ───────────────────
            _log('\n  STAGE 3: Suspicious Process', sid)
            _add_step(sid, 'STAGE_3_PROCESS')
            proc_name = f'payload_loader_{_rand_suffix()}.exe'
            evt = _build_event(
                'SUSPICIOUS_PROCESS', 'HIGH', sid,
                source_ip=src_ip,
                process_name=proc_name,
                process_pid=pid,
                attack_type='SUSPICIOUS_PROCESS', attack_mitre='T1059',
                description=f'Suspicious process spawned: {proc_name}',
            )
            _emit_event(evt)
            _log(f'     Process: {proc_name} (PID {pid})', sid)
            time.sleep(1.5)

            # ── Stage 4: Honeypot Interaction ─────────────────
            _log('\n  STAGE 4: Honeypot Interaction', sid)
            _add_step(sid, 'STAGE_4_HONEYPOT')
            _simulate_honeypot_access(sid, src_ip, proc_name, count=3)
            time.sleep(1)

            # ── Stage 5: File Activity ────────────────────────
            _log('\n  STAGE 5: File Activity (ML Detection)', sid)
            _add_step(sid, 'STAGE_5_FILES')
            os.makedirs(WATCHED_DIR, exist_ok=True)
            key = _rand_key()
            file_count = 0
            for base in ['ransomware_engine', 'crypto_locker', 'file_wiper']:
                fname = f'{base}_{_rand_suffix()}.dll'
                content = b'RANSOM_FULL_SIM ' + (b'X' * random.randint(200, 400))
                data = _add_pe_header(_xor_encrypt(content, key), ransomware=True)
                path = os.path.join(WATCHED_DIR, fname)
                with open(path, 'wb') as f:
                    f.write(data)
                file_count += 1

                evt = _build_event(
                    'FILE_RANSOMWARE_PAYLOAD', 'CRITICAL', sid,
                    source_ip=src_ip,
                    process_name=proc_name,
                    process_pid=pid,
                    attack_type='RANSOMWARE', attack_mitre='T1486',
                    file_name=fname,
                    description=f'Ransomware file created: {fname}',
                )
                _emit_event(evt)
                time.sleep(1.2)

            _log(f'     {file_count} malicious files deployed', sid)

            # ── Stage 6: Data Exfil ───────────────────────────
            _log('\n  STAGE 6: Data Exfiltration', sid)
            _add_step(sid, 'STAGE_6_EXFIL')
            mb_sim = round(random.uniform(75, 150), 1)
            exfil_evt = _build_event(
                'DATA_EXFILTRATION', 'CRITICAL', sid,
                source_ip=src_ip, dest_ip=local_ip,
                dest_port=443, protocol='HTTPS',
                attack_type='DATA_EXFIL', attack_mitre='T1041',
                description=f'Data exfiltration: {mb_sim} MB outbound',
            )
            exfil_evt['_exfil_mb'] = mb_sim
            _emit_event(exfil_evt)
            _log(f'     Exfiltration: {mb_sim} MB simulated', sid)
            time.sleep(1)

            # ── Stage 7: Ransom Note ──────────────────────────
            _log('\n  STAGE 7: Ransom Note', sid)
            _add_step(sid, 'STAGE_7_RANSOM_NOTE')
            note_path = os.path.join(WATCHED_DIR, 'READ_ME_NOW.txt')
            with open(note_path, 'w') as f:
                f.write(
                    f'[SIMULATION - NOT REAL RANSOMWARE]\n'
                    f'Scenario: {sid}\n'
                    f'YOUR FILES HAVE BEEN ENCRYPTED — THIS IS A DEMO\n'
                    f'BTC Address: 1SIMDEMO{_rand_suffix(20)}\n'
                )
            _log('     Ransom note dropped', sid)
            time.sleep(0.5)

            _log('\n  ✅ FULL ATTACK SIMULATION COMPLETE', sid)
            _log(f'     Source IP: {src_ip}', sid)
            _log(f'     Stages:    7/7', sid)
            _log(f'     Files:     {file_count} malicious payloads', sid)
            _log(f'     Honeypots: 3 triggered', sid)
            _add_step(sid, 'FULL_ATTACK_COMPLETE')

        except Exception as e:
            _log(f'❌ Full attack error: {e}', sid)
        finally:
            _end_scenario(sid)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return sid


# ─────────────────────────────────────────────────────────
# Honeypot helper
# ─────────────────────────────────────────────────────────

def _simulate_honeypot_access(
    scenario_id: str,
    src_ip: str,
    process_name: str,
    count: int = 1,
):
    """Simulate access to honeypot files and record triggers."""
    try:
        from utils.honeypot import HONEYPOT_FILES, record_trigger
        available = list(HONEYPOT_FILES.keys())
        chosen    = random.sample(available, min(count, len(available)))
        pid       = _get_current_pid()

        for resource in chosen:
            trigger = record_trigger(
                resource=resource,
                process_name=process_name,
                process_pid=pid,
                source_ip=src_ip,
                operation='READ',
                scenario_id=scenario_id,
            )

            evt = _build_event(
                'HONEYPOT_TRIGGERED', 'CRITICAL', scenario_id,
                source_ip=src_ip,
                process_name=process_name,
                process_pid=pid,
                attack_type='HONEYPOT_ACCESS',
                honeypot_triggered=True,
                honeypot_resource=resource,
                description=f'Honeypot accessed: {resource} by {process_name}',
            )
            _emit_event(evt)
            _log(f'     🍯 HONEYPOT: {resource} accessed by {process_name}', scenario_id)
            time.sleep(0.3)

    except Exception as e:
        _log(f'     ⚠️  Honeypot record failed: {e}', scenario_id)


# ─────────────────────────────────────────────────────────
# CLI dispatcher
# ─────────────────────────────────────────────────────────

SIMULATION_MAP = {
    'ransomware':          simulate_ransomware,
    'portscan':            simulate_portscan,
    'brute-force':         simulate_bruteforce,
    'phishing':            simulate_phishing,
    'suspicious-process':  simulate_suspicious_process,
    'data-exfiltration':   simulate_data_exfiltration,
    'honeypot':            simulate_honeypot_access,
    'full-attack':         simulate_full_attack,
}


def run_simulation(name: str, scenario_id: str = None) -> Optional[str]:
    fn = SIMULATION_MAP.get(name)
    if not fn:
        return None
    return fn(scenario_id=scenario_id)

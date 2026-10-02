#!/usr/bin/env python3
"""
CyberDefense CLI — Attack Simulation Terminal
Usage:
  python cyberdefense_cli.py simulate ransomware
  python cyberdefense_cli.py simulate portscan
  python cyberdefense_cli.py simulate brute-force
  python cyberdefense_cli.py simulate phishing
  python cyberdefense_cli.py simulate suspicious-process
  python cyberdefense_cli.py simulate data-exfiltration
  python cyberdefense_cli.py simulate honeypot
  python cyberdefense_cli.py simulate full-attack
  python cyberdefense_cli.py status
  python cyberdefense_cli.py events
  python cyberdefense_cli.py incidents
  python cyberdefense_cli.py stop
  python cyberdefense_cli.py reset
  python cyberdefense_cli.py help

Or run interactively:
  python cyberdefense_cli.py
"""
import sys
import os
import json
import time
import requests
from datetime import datetime

BASE_URL   = 'http://localhost:5000/api'
TOKEN_FILE = os.path.join(os.path.dirname(__file__), '.cli_token')

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║       🛡️  CYBERDEFENSE-AI — CYBER RANGE TERMINAL          ║
║          Safe Academic Simulation Environment             ║
╚═══════════════════════════════════════════════════════════╝
"""

HELP_TEXT = """
SIMULATIONS:
  simulate ransomware          — Ransomware attack + file encryption simulation
  simulate portscan            — Port scan reconnaissance simulation
  simulate brute-force         — Brute force authentication simulation
  simulate phishing            — Phishing attack chain simulation
  simulate suspicious-process  — Suspicious process activity simulation
  simulate data-exfiltration   — Data exfiltration simulation
  simulate honeypot            — Direct honeypot interaction simulation
  simulate full-attack         — Multi-stage complete attack simulation

SYSTEM:
  status     — Show SOC system status
  events     — Show recent security events
  incidents  — Show correlated incidents
  stop       — Stop active simulation
  reset      — Reset lab environment
  help       — Show this help

All simulations are SAFE and CONTROLLED.
No real malware, no real encryption, no unauthorized network access.
"""

SIMULATIONS = [
    'ransomware', 'portscan', 'brute-force', 'phishing',
    'suspicious-process', 'data-exfiltration', 'honeypot', 'full-attack',
]


def _get_token() -> str:
    """Get or refresh auth token."""
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE) as f:
                tok = f.read().strip()
            # Verify it still works
            r = requests.get(f'{BASE_URL}/verify-token',
                             headers={'Authorization': f'Bearer {tok}'}, timeout=3)
            if r.status_code == 200:
                return tok
    except Exception:
        pass

    # Re-login
    try:
        r = requests.post(f'{BASE_URL}/login',
                          json={'username': 'admin', 'password': 'admin123'}, timeout=5)
        if r.status_code == 200:
            tok = r.json().get('token', '')
            with open(TOKEN_FILE, 'w') as f:
                f.write(tok)
            return tok
    except Exception as e:
        print(f'⚠️  Cannot connect to backend: {e}')
        print(f'   Make sure the backend is running: python app.py')
        sys.exit(1)
    return ''


def _headers(token: str) -> dict:
    return {'Authorization': f'Bearer {token}'}


def _backend_available() -> bool:
    try:
        r = requests.get(f'{BASE_URL}/health', timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def cmd_simulate(sim_type: str, token: str):
    if sim_type not in SIMULATIONS:
        print(f'❌ Unknown simulation: {sim_type}')
        print(f'   Available: {", ".join(SIMULATIONS)}')
        return

    print(f'\n🚀 Starting simulation: {sim_type}')
    print('   Sending to backend...\n')

    try:
        r = requests.post(
            f'{BASE_URL}/lab/simulate',
            json={'type': sim_type},
            headers=_headers(token),
            timeout=10
        )
        data = r.json()
        if r.status_code == 200:
            sid = data.get('scenario_id', '?')
            print(f'✅ Simulation started!')
            print(f'   Scenario ID : {sid}')
            print(f'   Type        : {sim_type}')
            print(f'   Status      : RUNNING')
            print(f'\n   Watch the SOC dashboard: http://localhost:5173/soc')
            print(f'   Or stream logs: python cyberdefense_cli.py events\n')

            # Stream log output
            _stream_sim_log(sid, token)
        else:
            print(f'❌ Simulation failed: {data.get("error", "Unknown error")}')
    except requests.exceptions.ConnectionError:
        print('❌ Backend not reachable. Start it with: python app.py')
    except Exception as e:
        print(f'❌ Error: {e}')


def _stream_sim_log(scenario_id: str, token: str, timeout: int = 60):
    """Stream simulation log output until complete or timeout."""
    seen = set()
    start = time.time()
    print(f'--- Streaming simulation output (Ctrl+C to stop) ---')

    while time.time() - start < timeout:
        try:
            r = requests.get(
                f'{BASE_URL}/lab/logs/{scenario_id}',
                headers=_headers(token),
                timeout=5
            )
            if r.status_code == 200:
                logs = r.json().get('logs', [])
                for entry in logs:
                    key = entry.get('timestamp', '') + entry.get('message', '')
                    if key not in seen:
                        seen.add(key)
                        ts  = entry.get('timestamp', '')[:19].replace('T', ' ')
                        msg = entry.get('message', '')
                        print(f'  [{ts}] {msg}')

            # Check if done
            status_r = requests.get(
                f'{BASE_URL}/lab/status',
                headers=_headers(token),
                timeout=3
            )
            if status_r.status_code == 200:
                st = status_r.json()
                active = st.get('active_scenario')
                if active is None:
                    print(f'\n--- Simulation complete ---\n')
                    return

        except KeyboardInterrupt:
            print('\n--- Stopped ---')
            return
        except Exception:
            pass
        time.sleep(1)


def cmd_status(token: str):
    try:
        r = requests.get(f'{BASE_URL}/lab/status', headers=_headers(token), timeout=5)
        data = r.json()
        print('\n📊 SYSTEM STATUS')
        print('─' * 40)
        print(f'  ML Engine    : {"✅ ONLINE" if data.get("ml_online") else "⚠️  OFFLINE"}')
        print(f'  Blockchain   : {"✅ " + data.get("blockchain_mode","?").upper()}')
        print(f'  Honeypot     : {"✅ ACTIVE" if data.get("honeypot_active") else "⚠️  INACTIVE"}')
        print(f'  Lab Mode     : {"🔬 CYBER LAB" if data.get("lab_mode") else "🛡️  MONITORING"}')
        active = data.get('active_scenario')
        if active:
            print(f'  Active Sim   : {active}')
        else:
            print(f'  Active Sim   : None')
        print()
    except Exception as e:
        print(f'❌ Status error: {e}')


def cmd_events(token: str):
    try:
        r = requests.get(f'{BASE_URL}/events?limit=20', headers=_headers(token), timeout=5)
        events = r.json().get('events', [])
        print(f'\n📡 RECENT SECURITY EVENTS ({len(events)})')
        print('─' * 60)
        for ev in events[:15]:
            ts   = (ev.get('timestamp', '')[:19] or '').replace('T', ' ')
            sev  = ev.get('severity', 'LOW').ljust(8)
            etype = ev.get('event_type', '?')[:30].ljust(30)
            desc = ev.get('description', '')[:40]
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(ev.get('severity', 'LOW'), '⚪')
            print(f'  {icon} {ts} {etype} {desc}')
        print()
    except Exception as e:
        print(f'❌ Events error: {e}')


def cmd_incidents(token: str):
    try:
        r = requests.get(f'{BASE_URL}/incidents', headers=_headers(token), timeout=5)
        incidents = r.json().get('incidents', [])
        print(f'\n🚨 INCIDENTS ({len(incidents)})')
        print('─' * 60)
        for inc in incidents[:10]:
            ts      = (inc.get('created_at', '')[:19] or '').replace('T', ' ')
            title   = (inc.get('title') or inc.get('attack_type', '?'))[:35].ljust(35)
            score   = inc.get('risk_score', 0)
            level   = inc.get('risk_level', '?')
            status  = inc.get('status', '?')
            icon    = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡', 'LOW': '🟢'}.get(level, '⚪')
            print(f'  {icon} {ts} {title} {score:5.1f}/100 [{status}]')
        print()
    except Exception as e:
        print(f'❌ Incidents error: {e}')


def cmd_stop(token: str):
    try:
        r = requests.post(f'{BASE_URL}/lab/stop', headers=_headers(token), timeout=5)
        print(f'✅ {r.json().get("message", "Simulation stopped")}')
    except Exception as e:
        print(f'❌ Stop error: {e}')


def cmd_reset(token: str):
    confirm = input('Reset lab environment? This clears simulation data. (y/N): ').strip().lower()
    if confirm == 'y':
        try:
            r = requests.post(f'{BASE_URL}/lab/reset', headers=_headers(token), timeout=5)
            print(f'✅ {r.json().get("message", "Lab reset")}')
        except Exception as e:
            print(f'❌ Reset error: {e}')
    else:
        print('Reset cancelled.')


def run_command(args: list):
    print(BANNER)

    if not _backend_available():
        print('❌ Backend is not running.')
        print('   Start it with: cd backend && python app.py\n')
        sys.exit(1)

    token = _get_token()

    if not args or args[0] == 'help':
        print(HELP_TEXT)
        return

    cmd = args[0]

    if cmd == 'simulate':
        if len(args) < 2:
            print('Usage: simulate <type>')
            print(f'Types: {", ".join(SIMULATIONS)}')
            return
        cmd_simulate(args[1], token)

    elif cmd == 'status':
        cmd_status(token)

    elif cmd == 'events':
        cmd_events(token)

    elif cmd == 'incidents':
        cmd_incidents(token)

    elif cmd == 'stop':
        cmd_stop(token)

    elif cmd == 'reset':
        cmd_reset(token)

    else:
        print(f'Unknown command: {cmd}')
        print(HELP_TEXT)


def interactive_mode():
    print(BANNER)

    if not _backend_available():
        print('❌ Backend is not running.')
        print('   Start it with: cd backend && python app.py\n')
        sys.exit(1)

    token = _get_token()
    print('Type "help" for available commands. Type "exit" to quit.\n')

    while True:
        try:
            line = input('cyberdefense> ').strip()
        except (KeyboardInterrupt, EOFError):
            print('\nExiting...')
            break

        if not line:
            continue
        if line in ('exit', 'quit', 'q'):
            break

        parts = line.split()
        run_command(parts)
        # Refresh token after each command (may expire)
        token = _get_token()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_command(sys.argv[1:])
    else:
        interactive_mode()

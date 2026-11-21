"""Quick end-to-end test for the ransomware simulation pipeline."""
import requests
import time
import sys

BASE = 'http://localhost:5000'

r = requests.post(f'{BASE}/api/login', json={'username': 'admin', 'password': 'admin123'})
token = r.json()['token']
h = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

print("=== RANSOMWARE SIMULATION TEST ===\n")

# Enable lab mode
requests.post(f'{BASE}/api/lab/mode', json={'enabled': True}, headers=h)
requests.post(f'{BASE}/api/lab/stop', json={}, headers=h)
time.sleep(1)

# Start ransomware simulation
r2 = requests.post(f'{BASE}/api/lab/simulate', json={'type': 'ransomware'}, headers=h)
resp = r2.json()
sid = resp.get('scenario_id', '')
print(f"Scenario started : {sid}")
print(f"Response         : {resp.get('message','')}")

# Wait for files to be dropped + scanned
print("\nWaiting 18s for file drops + ML scan pipeline...")
time.sleep(18)

# Check incidents
incs = requests.get(f'{BASE}/api/incidents', headers=h).json().get('incidents', [])
mine = [i for i in incs if i.get('scenario_id') == sid]

print(f"\n--- Results ---")
print(f"Total incidents for scenario: {len(mine)}")

for i in mine:
    atk   = i.get('attack_type', 'UNKNOWN')
    score = i.get('risk_score', 0)
    sev   = i.get('severity', '?')
    fname = (i.get('file_name') or '')[:35]
    print(f"  [{sev:8}] {atk:35} risk={score:5.1f}  file={fname}")

# Check threats (file monitor quarantine)
threats = requests.get(f'{BASE}/api/threats', headers=h).json()
ransomware_threats = [t for t in threats if 'Ransomware' in str(t.get('prediction', ''))]
print(f"\nRansomware threats in DB : {len(ransomware_threats)}")
for t in ransomware_threats[-3:]:
    print(f"  {t.get('file_name','?'):40} score={t.get('threat_score',0)}")

# Check events
events = requests.get(f'{BASE}/api/events', headers=h).json().get('events', [])
sim_events = [e for e in events if e.get('scenario_id') == sid]
print(f"\nSecurity events for scenario: {len(sim_events)}")
for e in sim_events[:5]:
    print(f"  [{e.get('severity','?'):8}] {e.get('event_type','?'):35} {e.get('description','')[:50]}")

print("\n=== DONE ===")
print("If incidents show risk > 0 and file_name is set → pipeline is working.")
print("Check Dashboard > Incidents and Cyber Lab terminal for live_incident events.")

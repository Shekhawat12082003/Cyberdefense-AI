"""Run all lab simulations in sequence."""
import requests, time

BASE = 'http://localhost:5000'
r = requests.post(f'{BASE}/api/login', json={'username': 'admin', 'password': 'admin123'})
token = r.json()['token']
h = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

requests.post(f'{BASE}/api/lab/mode', json={'enabled': True}, headers=h)
requests.post(f'{BASE}/api/lab/stop', json={}, headers=h)
time.sleep(0.5)

types = ['portscan', 'brute-force', 'ransomware', 'data-exfiltration', 'honeypot', 'full-attack']

for t in types:
    requests.post(f'{BASE}/api/lab/stop', json={}, headers=h)
    time.sleep(0.5)
    r2 = requests.post(f'{BASE}/api/lab/simulate', json={'type': t}, headers=h)
    sid = r2.json().get('scenario_id', '?')
    print(f"  [{t:20}] started → {sid}")
    time.sleep(10)

print("\nAll simulations complete — check dashboard!")

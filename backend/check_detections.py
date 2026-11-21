import requests

r = requests.post('http://localhost:5000/api/login', json={'username': 'admin', 'password': 'admin123'})
h = {'Authorization': 'Bearer ' + r.json()['token']}

# Network stats
ns = requests.get('http://localhost:5000/api/network/stats', headers=h).json()
print("=== NETWORK MONITOR STATE ===")
print(f"  Capture mode      : {ns.get('capture_mode')}")
print(f"  Packets captured  : {ns.get('packets_captured')}")
print(f"  Scans detected    : {ns.get('scans_detected')}")
print(f"  Brute force det.  : {ns.get('brute_force_detected')}")
print(f"  Suspicious IPs    : {ns.get('suspicious_ips')}")
print(f"  Alerts today      : {ns.get('alerts_today')}")

# Network alerts
na = requests.get('http://localhost:5000/api/network/alerts', headers=h).json()
alerts = na.get('alerts', [])
print(f"\n=== NETWORK ALERTS: {len(alerts)} ===")
for a in alerts[:5]:
    print(f"  [{a.get('severity')}] {a.get('attack_type')} from {a.get('attacker_ip') or a.get('src_ip')} conf={a.get('confidence')}%")

# All incidents
incs = requests.get('http://localhost:5000/api/incidents', headers=h).json().get('incidents', [])
print(f"\n=== INCIDENTS (total {len(incs)}) ===")
for i in incs[:8]:
    sid = (i.get('scenario_id') or '')[:20]
    print(f"  [{i.get('severity'):8}] {i.get('attack_type'):35} risk={i.get('risk_score',0):5.1f}  sid={sid}")

# Threats (file monitor)
threats = requests.get('http://localhost:5000/api/threats', headers=h).json()
high = [t for t in threats if t.get('threat_score', 0) > 40]
print(f"\n=== HIGH THREATS (file monitor, score>40): {len(high)} ===")
for t in high[:5]:
    print(f"  {t.get('file_name','?'):40} score={t.get('threat_score')} pred={t.get('prediction')}")

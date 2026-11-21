"""Check if the event callback is registered and trace what happens during simulation."""
import requests, time, sys

BASE = 'http://localhost:5000'

r = requests.post(f'{BASE}/api/login', json={'username': 'admin', 'password': 'admin123'})
token = r.json()['token']
h = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

# Check how many callbacks are registered
sys.path.insert(0, 'backend')
from utils.attack_director import _event_callbacks, _output_callbacks
print(f"Registered event callbacks : {len(_event_callbacks)}")
print(f"Registered output callbacks: {len(_output_callbacks)}")

# Also check lab status
ls = requests.get(f'{BASE}/api/lab/status', headers=h).json()
print(f"Lab status: {ls}")

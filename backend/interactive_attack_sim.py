#!/usr/bin/env python3
"""
Interactive Attack Simulator
Configure and run cyber attacks with full control over parameters.
Usage: python interactive_attack_sim.py
"""

import sys
import os
import time
import random
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.incident_manager import create_incident, get_all_incidents


class InteractiveSimulator:
    def __init__(self):
        self.running = False

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
        print()

        type_choice = self.get_number("Select attack type", 1, 7, 7)

        attack_types = {
            1: "portscan",
            2: "bruteforce",
            3: "synflood",
            4: "dataexfil",
            5: "ransomware",
            6: "c2beacon",
            7: "full-attack"
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

        # Attack-specific configuration
        attack_config = {
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "target_ip": target_ip,
            "target_port": target_port,
            "cycles": cycles,
            "intensity": intensity_choice
        }

        # Additional parameters based on attack type
        if attack_type in ["bruteforce", "portscan"]:
            print("\nBRUTE FORCE / PORT SCAN OPTIONS:")
            num_threads = self.get_number("Number of threads", 1, 100, 10)
            attack_config["threads"] = num_threads

        if attack_type == "synflood":
            print("\nDOS OPTIONS:")
            packet_rate = self.get_number("Packets per second", 10, 1000, 100)
            attack_config["packet_rate"] = packet_rate

        if attack_type == "ransomware":
            print("\nRANSOMWARE OPTIONS:")
            encrypt_files = self.get_choice("Encrypt files", ["Y", "N"], "Y") == "Y"
            drop_ransom_note = self.get_choice("Drop ransom note", ["Y", "N"], "Y") == "Y"
            attack_config["encrypt_files"] = encrypt_files
            attack_config["drop_ransom_note"] = drop_ransom_note

        if attack_type == "dataexfil":
            print("\nDATA EXFILTRATION OPTIONS:")
            data_size = self.get_number("Data size (MB)", 1, 1000, 50)
            attack_config["data_size"] = data_size

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
        if "threads" in attack_config:
            print(f"Threads:         {attack_config['threads']}")
        if "packet_rate" in attack_config:
            print(f"Packet Rate:     {attack_config['packet_rate']}/sec")
        if "encrypt_files" in attack_config:
            print(f"Encrypt Files:   {attack_config['encrypt_files']}")
            print(f"Ransom Note:     {attack_config['drop_ransom_note']}")
        if "data_size" in attack_config:
            print(f"Data Size:       {attack_config['data_size']} MB")
        print("="*60)

        confirm = self.get_choice("Start attack?", ["Y", "N"], "Y")
        if confirm == "N":
            print("Attack cancelled.")
            return None

        return attack_config

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
            for cycle in range(1, config['cycles'] + 1):
                if not self.running:
                    print("\nAttack stopped by user.")
                    break

                print(f"\n[Cycle {cycle}/{config['cycles']}]")

                # Generate attack events based on type
                self._generate_attack_event(config, cycle)

                # Delay between cycles
                delay = random.uniform(1, 3)
                time.sleep(delay)

            print("\n" + "-" * 60)
            print("Attack completed successfully!")
            print(f"Total cycles executed: {cycle}")

        except KeyboardInterrupt:
            print("\n\nAttack stopped by user.")
        finally:
            self.running = False

    def _generate_attack_event(self, config, cycle):
        """Generate attack event based on configuration"""
        attack_type = config['attack_type']
        attacker_ip = config['attacker_ip']
        target_ip = config['target_ip']
        target_port = config['target_port']

        # Severity based on intensity
        severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}
        severity = severity_map.get(config['intensity'], "MEDIUM")

        # Generate scenario_id for geolocation enhancement
        import uuid
        scenario_id = f"interactive_{config['attack_type']}_{uuid.uuid4().hex[:8]}"

        # Generate enhanced geolocation data for simulation
        from utils.geo_lookup import format_geo_display
        mock_locations = [
            {'city': 'Moscow', 'region': 'Moscow Oblast', 'country': 'RU', 'isp': 'RosTelecom', 'asn': 'AS12389', 'org': 'Russian Research Network'},
            {'city': 'Beijing', 'region': 'Beijing', 'country': 'CN', 'isp': 'China Telecom', 'asn': 'AS4134', 'org': 'China Telecom Backbone'},
            {'city': 'Pyongyang', 'region': 'Pyongyang', 'country': 'KP', 'isp': 'StarLink', 'asn': 'AS131696', 'org': 'Korean Central News Agency'},
            {'city': 'Tehran', 'region': 'Tehran', 'country': 'IR', 'isp': 'Telecommunication Company', 'asn': 'AS12880', 'org': 'Iran Telecom'},
            {'city': 'Shanghai', 'region': 'Shanghai', 'country': 'CN', 'isp': 'China Unicom', 'asn': 'AS4837', 'org': 'China Unicom Network'},
        ]
        mock = random.choice(mock_locations)
        geo_info = {
            'type': 'simulated',
            'display': f"{mock['city']}, {mock['country']}",
            'country': mock['country'],
            'region': mock['region'],
            'city': mock['city'],
            'lat': None,
            'lon': None,
            'isp': mock['isp'],
            'asn': mock['asn'],
            'org': mock['org'],
            'timezone': 'UTC',
            'source': 'Interactive Simulator',
            'note': 'SIMULATED GEOLOCATION — for training exercise only',
        }

        # Create incident
        if attack_type == "portscan":
            ports_scanned = random.randint(10, 100)
            print(f"  Scanning {ports_scanned} ports on {target_ip}")
            create_incident(
                attack_type="PORT_SCAN",
                title=f"Port scan from {attacker_ip}",
                severity=severity,
                source_ip=attacker_ip,
                dest_ip=target_ip,
                dest_port=target_port,
                network_severity=severity,
                scenario_id=scenario_id,
                geo_info=geo_info
            )

        elif attack_type == "bruteforce":
            attempts = random.randint(5, 50)
            print(f"  Brute force: {attempts} login attempts on {target_ip}:{target_port}")
            create_incident(
                attack_type="BRUTE_FORCE",
                title=f"Brute force attack from {attacker_ip}",
                severity=severity,
                source_ip=attacker_ip,
                dest_ip=target_ip,
                dest_port=target_port,
                network_severity=severity,
                scenario_id=scenario_id,
                geo_info=geo_info
            )

        elif attack_type == "synflood":
            packets = config.get('packet_rate', 100)
            print(f"  SYN Flood: {packets} packets/sec to {target_ip}:{target_port}")
            create_incident(
                attack_type="SYN_FLOOD",
                title=f"SYN Flood attack from {attacker_ip}",
                severity="HIGH",
                source_ip=attacker_ip,
                dest_ip=target_ip,
                dest_port=target_port,
                network_severity="HIGH",
                scenario_id=scenario_id,
                geo_info=geo_info
            )

        elif attack_type == "dataexfil":
            size = config.get('data_size', 50)
            print(f"  Data exfiltration: {size} MB from {target_ip}")
            create_incident(
                attack_type="DATA_EXFIL",
                title=f"Data exfiltration from {attacker_ip}",
                severity="HIGH",
                source_ip=attacker_ip,
                dest_ip=target_ip,
                network_severity="HIGH",
                scenario_id=scenario_id,
                geo_info=geo_info
            )

        elif attack_type == "ransomware":
            print(f"  Ransomware payload dropped on {target_ip}")
            if config.get('encrypt_files', True):
                print(f"  Files encrypted")
            if config.get('drop_ransom_note', True):
                print(f"  Ransom note dropped")
            create_incident(
                attack_type="RANSOMWARE",
                title=f"Ransomware attack from {attacker_ip}",
                severity="CRITICAL",
                source_ip=attacker_ip,
                dest_ip=target_ip,
                network_severity="CRITICAL",
                scenario_id=scenario_id,
                geo_info=geo_info
            )

        elif attack_type == "c2beacon":
            print(f"  C2 beacon from {attacker_ip} to command server")
            create_incident(
                attack_type="C2_BEACON",
                title=f"C2 beacon from {attacker_ip}",
                severity="HIGH",
                source_ip=attacker_ip,
                dest_ip=target_ip,
                network_severity="HIGH",
                scenario_id=scenario_id,
                geo_info=geo_info
            )

        elif attack_type == "full-attack":
            # Mixed attack - generate multiple attack types
            attacks = ["PORT_SCAN", "BRUTE_FORCE", "SYN_FLOOD", "DATA_EXFIL", "C2_BEACON"]
            for i, atk in enumerate(attacks):
                if i > 0 and i % 2 == 0:
                    time.sleep(0.5)
                print(f"  {atk} from {attacker_ip}")
                create_incident(
                    attack_type=atk,
                    title=f"{atk} from {attacker_ip}",
                    severity=severity,
                    source_ip=attacker_ip,
                    dest_ip=target_ip,
                    dest_port=target_port,
                    network_severity=severity,
                    scenario_id=scenario_id,
                    geo_info=geo_info
                )

        print(f"  ✓ Incident created (Scenario: {scenario_id}, Geo: {geo_info['display']})")

    def main(self):
        """Main entry point"""
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
                self.view_incidents()
                input("\nPress Enter to continue...")

            elif choice == 3:
                print("\nExiting...")
                sys.exit(0)

    def view_incidents(self):
        """View recent incidents"""
        try:
            incidents = get_all_incidents(limit=10)

            if not incidents:
                print("No incidents found.")
                return

            print("\nRECENT INCIDENTS:")
            print("-" * 80)
            for inc in incidents:
                print(f"ID: {inc['id'][:12]}")
                print(f"Type: {inc['attack_type']}")
                print(f"Severity: {inc['severity']}")
                print(f"Source: {inc['source_ip']}")
                print(f"Target: {inc['dest_ip']}:{inc['dest_port']}")
                print(f"Risk Score: {inc['risk_score']}")
                print(f"Status: {inc['status']}")
                print("-" * 80)

        except Exception as e:
            print(f"Error viewing incidents: {e}")


if __name__ == "__main__":
    simulator = InteractiveSimulator()
    simulator.main()

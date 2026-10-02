import os
import sys
import time
import struct
import random
import string

# ── Config ────────────────────────────────────────────────
WATCHED_DIR = os.path.join(os.path.dirname(__file__), 'watched')
os.makedirs(WATCHED_DIR, exist_ok=True)

BANNER = """
╔══════════════════════════════════════════════════════╗
║       🦠 RANSOMWARE SIMULATOR — FOR TESTING ONLY     ║
║         CyberDefense AI Platform — Safe Demo         ║
╚══════════════════════════════════════════════════════╝
"""

# ── Randomization helpers ─────────────────────────────────

def rand_key() -> bytes:
    """Random XOR key each run."""
    length = random.randint(16, 64)
    return bytes(random.randint(0, 255) for _ in range(length))

def rand_btc_address() -> str:
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    return '1' + ''.join(random.choices(chars, k=random.randint(25, 33)))

def rand_email() -> str:
    domains = ['darkweb.onion', 'protonmail.com', 'tutanota.com', 'cock.li']
    user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 12)))
    return f"{user}@{random.choice(domains)}"

def rand_hours() -> int:
    return random.choice([24, 48, 72, 96])

def rand_btc_amount() -> float:
    return round(random.uniform(0.1, 2.5), 2)

def rand_ransom_note() -> str:
    amount  = rand_btc_amount()
    address = rand_btc_address()
    email   = rand_email()
    hours   = rand_hours()
    id_     = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    return f"""
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!          YOUR FILES ARE ENCRYPTED               !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

All your important files have been encrypted with AES-256.

YOUR UNIQUE ID: {id_}

To recover your files send {amount} BTC to:
{address}

Contact: {email}
You have {hours} hours before permanent deletion.

[THIS IS A SIMULATION - NOT REAL RANSOMWARE]

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""

def rand_content(label: str, size_range=(30, 80)) -> bytes:
    """Generate random-length content with a label so each file differs."""
    reps = random.randint(*size_range)
    noise = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=random.randint(8, 24)))
    return f'{label} {noise} '.encode() * reps

def rand_filename(base: str, ext: str) -> str:
    """Append a short random suffix so filenames differ each run."""
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{base}_{suffix}{ext}"

def rand_delay(base: float) -> float:
    """Jitter ±40% around base delay."""
    return round(base * random.uniform(0.6, 1.4), 2)


def generate_random_thresholds() -> dict:
    """Generate random threat score thresholds (0-100 scale).
    Returns: {'low_max': X, 'medium_max': Y} where LOW=0-X, MEDIUM=X-Y, HIGH=Y-100
    """
    low_max = round(random.uniform(20, 35), 1)      # LOW: 0 to 20-35
    medium_max = round(random.uniform(65, 80), 1)   # MEDIUM: LOW to 65-80, HIGH: 65-80 to 100
    return {'low_max': low_max, 'medium_max': medium_max}


# ── Core helpers ──────────────────────────────────────────

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def add_fake_pe_header(data: bytes, ransomware_mode: bool = True) -> bytes:
    mz           = b'MZ'
    pe           = b'PE\x00\x00'
    machine      = struct.pack('<H', random.choice([0x014c, 0x8664, 0x01c0]))
    num_sections = struct.pack('<H', random.randint(5, 9) if ransomware_mode else random.randint(2, 4))
    dll_chars    = struct.pack('<H', random.choice([0x0000, 0x0002]) if ransomware_mode else 0x8540)
    stack_size   = struct.pack('<I', random.choice([131072, 262144, 524288]) if ransomware_mode else random.choice([1048576, 2097152]))
    # Random BTC-style marker for ransomware, random noise for benign
    if ransomware_mode:
        marker = f'1BTC_RANSOM_{rand_btc_address()[:8]}_'.encode()[:20]
    else:
        marker = bytes(random.randint(0, 255) for _ in range(20))
    header = (
        mz + b'\x00' * 58 +
        pe + machine + num_sections +
        b'\x00' * 12 + dll_chars +
        stack_size + b'\x00' * 16 + marker
    )
    return header + data


def drop_ransom_note():
    path = os.path.join(WATCHED_DIR, 'READ_ME_NOW.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(rand_ransom_note())
    print(f"   📝 Ransom note dropped: READ_ME_NOW.txt")


def clean_watched_folder():
    files = os.listdir(WATCHED_DIR)
    if not files:
        print("\n   Watched folder already empty\n")
        return
    for f in files:
        path = os.path.join(WATCHED_DIR, f)
        try:
            os.remove(path)
            print(f"   Removed: {f}")
        except Exception as e:
            print(f"   Could not remove {f}: {e}")
    print(f"\n   Cleaned {len(files)} files\n")


# ─────────────────────────────────────────────────────────
# ATTACK MODES
# ─────────────────────────────────────────────────────────

def simulate_full_ransomware_attack(delay: float = 2.0):
    """All HIGH threat files — tests auto-quarantine."""
    print(BANNER)
    print("🦠 FULL RANSOMWARE ATTACK SIMULATION")
    print("=" * 55)
    
    thresholds = generate_random_thresholds()
    print(f"\n🎯 THREAT SCORE THRESHOLDS (Random):")
    print(f"   🟢 LOW    : 0.0 — {thresholds['low_max']}")
    print(f"   🟡 MEDIUM : {thresholds['low_max']} — {thresholds['medium_max']}")
    print(f"   🔴 HIGH   : {thresholds['medium_max']} — 100.0\n")

    key = rand_key()

    # Randomised file names and content each run
    base_files = [
        ('document',      '.txt', b'Sensitive company data employee records financial info '),
        ('financial_data','.csv', b'Name,Amount,Account\nEmployee,'),
        ('config',        '.json',b'{"api_key": "'),
        ('backup',        '.db',  b'SQLite format 3\x00Database records '),
        ('secret_keys',   '.pem', b'-----BEGIN RSA PRIVATE KEY-----\n'),
    ]
    test_files = []
    for base, ext, seed in base_files:
        fname   = rand_filename(base, ext)
        content = seed + rand_content(base, (20, 60))
        test_files.append((fname, content))

    print("\n📁 PHASE 1: Creating target files...")
    created = []
    for filename, content in test_files:
        path = os.path.join(WATCHED_DIR, filename)
        with open(path, 'wb') as f:
            f.write(content)
        created.append(path)
        print(f"   📄 Created: {filename}")

    actual_delay = rand_delay(delay)
    print(f"   Waiting {actual_delay}s before encryption...")
    time.sleep(actual_delay)

    print("\n" + "=" * 55)
    print("🔒 PHASE 2: ENCRYPTING FILES...")
    for filepath in created:
        filename = os.path.basename(filepath)
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            encrypted   = xor_encrypt(data, key)
            final       = add_fake_pe_header(encrypted, ransomware_mode=True)
            locked_path = filepath + '.locked'
            with open(locked_path, 'wb') as f:
                f.write(final)
            os.remove(filepath)
            print(f"   🔒 {filename} → {filename}.locked")
            time.sleep(rand_delay(delay * 0.5))
        except Exception as e:
            print(f"   ❌ Failed: {filename} — {e}")

    print("\n📝 PHASE 3: Dropping ransom note...")
    drop_ransom_note()

    print(f"\n{'=' * 55}")
    print(f"🦠 ATTACK COMPLETE!")
    print(f"   Files encrypted : {len(created)}")
    print(f"   Watch backend for HIGH THREAT alerts!")
    print(f"{'=' * 55}\n")


def simulate_mixed_attack(delay: float = 1.5):
    """Mix of HIGH + MEDIUM + LOW — best for demo."""
    print(BANNER)
    print("🎯 MIXED ATTACK SIMULATION — Best for Demo")
    print("=" * 55)
    
    thresholds = generate_random_thresholds()
    print(f"\n🎯 THREAT SCORE THRESHOLDS (Random):")
    print(f"   🟢 LOW    : 0.0 — {thresholds['low_max']}")
    print(f"   🟡 MEDIUM : {thresholds['low_max']} — {thresholds['medium_max']}")
    print(f"   🔴 HIGH   : {thresholds['medium_max']} — 100.0\n")

    key = rand_key()

    high_bases   = ['ransomware_payload', 'encrypted_locker', 'crypto_miner', 'keylogger', 'wiper']
    medium_bases = ['suspicious_tool', 'unknown_packer', 'obfuscated_loader', 'dropper_stage2']
    low_bases    = ['calc', 'notepad_helper', 'ui_helper', 'font_renderer', 'audio_lib']

    # Pick random subset each run
    high_picks   = random.sample(high_bases,   k=random.randint(2, 3))
    medium_picks = random.sample(medium_bases, k=random.randint(1, 2))
    low_picks    = random.sample(low_bases,    k=random.randint(1, 2))

    files = []
    for b in high_picks:
        ext = random.choice(['.dll', '.exe'])
        files.append((rand_filename(b, ext), True,  rand_content(b, (40, 80)), 'HIGH'))
    for b in medium_picks:
        ext = random.choice(['.dll', '.exe'])
        files.append((rand_filename(b, ext), False, rand_content(b, (30, 60)), 'MEDIUM'))
    for b in low_picks:
        files.append((rand_filename(b, '.dll'), False, rand_content(b, (40, 70)), 'LOW'))

    random.shuffle(files)  # randomise drop order

    print(f"\n📁 Creating {len(files)} files (HIGH + MEDIUM + LOW)...\n")

    for filename, is_ransomware, content, level in files:
        filepath = os.path.join(WATCHED_DIR, filename)
        if is_ransomware:
            encrypted = xor_encrypt(content, key)
            final     = add_fake_pe_header(encrypted, ransomware_mode=True)
        elif level == 'MEDIUM':
            marked = b'HEUR_SUSP_PACKED:' + content
            final  = add_fake_pe_header(marked, ransomware_mode=False)
        else:
            final = add_fake_pe_header(content, ransomware_mode=False)

        with open(filepath, 'wb') as f:
            f.write(final)

        icon = '🔴' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
        print(f"   {icon} [{level}] {filename}")
        time.sleep(rand_delay(delay))

    print(f"\n{'=' * 55}")
    print(f"🎯 MIXED ATTACK COMPLETE!")
    print(f"   HIGH   : {sum(1 for f in files if f[3] == 'HIGH')} files")
    print(f"   MEDIUM : {sum(1 for f in files if f[3] == 'MEDIUM')} files")
    print(f"   LOW    : {sum(1 for f in files if f[3] == 'LOW')} files")
    print(f"   Watch dashboard for mixed threat levels!")
    print(f"{'=' * 55}\n")


def simulate_gradual_escalation(delay: float = 2.0):
    """APT simulation — LOW to HIGH escalation."""
    print(BANNER)
    print("📈 GRADUAL ESCALATION — APT Simulation")
    print("=" * 55)
    
    thresholds = generate_random_thresholds()
    print(f"\n🎯 THREAT SCORE THRESHOLDS (Random):")
    print(f"   🟢 LOW    : 0.0 — {thresholds['low_max']}")
    print(f"   🟡 MEDIUM : {thresholds['low_max']} — {thresholds['medium_max']}")
    print(f"   🔴 HIGH   : {thresholds['medium_max']} — 100.0\n")

    key = rand_key()

    stage_templates = [
        ('recon',       False, 'LOW',    "Stage 1: Reconnaissance"),
        ('dropper',     False, 'MEDIUM', "Stage 2: Dropper"),
        ('persist',     False, 'MEDIUM', "Stage 3: Persistence"),
        ('encrypt_eng', True,  'HIGH',   "Stage 4: Encryption Engine"),
        ('ransom_final',True,  'HIGH',   "Stage 5: Ransom Payload"),
    ]

    for i, (base, is_ransomware, level, stage_name) in enumerate(stage_templates, 1):
        ext      = random.choice(['.dll', '.exe'])
        filename = rand_filename(f"stage{i}_{base}", ext)
        content  = rand_content(base, (40, 70))
        filepath = os.path.join(WATCHED_DIR, filename)

        print(f"\n   ⏳ {stage_name}")

        if is_ransomware:
            encrypted = xor_encrypt(content, key)
            final     = add_fake_pe_header(encrypted, ransomware_mode=True)
        elif level == 'MEDIUM':
            marked = b'HEUR_SUSP_PACKED:' + content
            final  = add_fake_pe_header(marked, ransomware_mode=False)
        else:
            final = add_fake_pe_header(content, ransomware_mode=False)

        with open(filepath, 'wb') as f:
            f.write(final)

        icon = '🔴' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
        actual_delay = rand_delay(delay)
        print(f"   {icon} Deployed: {filename} [{level}]")
        print(f"   Waiting {actual_delay}s for next stage...")
        time.sleep(actual_delay)

    drop_ransom_note()

    print(f"\n{'=' * 55}")
    print(f"📈 APT SIMULATION COMPLETE!")
    print(f"   Watch dashboard — threat level should escalate!")
    print(f"{'=' * 55}\n")


def simulate_benign_files(count: int = 5):
    """All benign files — tests false positive rate."""
    print(BANNER)
    print(f"✅ BENIGN FILES SIMULATION ({count} files)")
    print("=" * 55)
    
    thresholds = generate_random_thresholds()
    print(f"\n🎯 THREAT SCORE THRESHOLDS (Random):")
    print(f"   🟢 LOW    : 0.0 — {thresholds['low_max']}")
    print(f"   🟡 MEDIUM : {thresholds['low_max']} — {thresholds['medium_max']}")
    print(f"   🔴 HIGH   : {thresholds['medium_max']} — 100.0\n")

    name_pool = [
        'system_helper', 'winapi_wrapper', 'graphics_engine', 'audio_driver',
        'network_utils', 'ui_framework', 'database_lib', 'crypto_utils',
        'font_renderer', 'input_handler', 'logger_lib', 'config_parser',
    ]

    for i in range(count):
        base     = random.choice(name_pool)
        filename = rand_filename(f"benign_{i+1}_{base}", '.dll')
        filepath = os.path.join(WATCHED_DIR, filename)
        content  = rand_content(f'Normal application data safe content {base}', (40, 70))
        final    = add_fake_pe_header(content, ransomware_mode=False)
        with open(filepath, 'wb') as f:
            f.write(final)
        print(f"   ✅ Created: {filename}")
        time.sleep(rand_delay(1.0))

    print(f"\n   Monitor should score ALL files LOW risk")
    print(f"   No quarantine should trigger\n")


def quick_single_file():
    """Create one file with chosen risk level."""
    thresholds = generate_random_thresholds()
    print(f"\n🎯 THREAT SCORE THRESHOLDS (Random):")
    print(f"   🟢 LOW    : 0.0 — {thresholds['low_max']}")
    print(f"   🟡 MEDIUM : {thresholds['low_max']} — {thresholds['medium_max']}")
    print(f"   🔴 HIGH   : {thresholds['medium_max']} — 100.0\n")
    
    print("  Risk level:")
    print("  1 — HIGH (ransomware)")
    print("  2 — MEDIUM (suspicious)")
    print("  3 — LOW (benign)")
    choice = input("  Choose: ").strip()

    key = rand_key()
    ts  = int(time.time())

    if choice == '1':
        base     = random.choice(['malware', 'payload', 'locker', 'cryptor', 'wiper'])
        filename = rand_filename(base, random.choice(['.dll', '.exe']))
        content  = rand_content('Ransomware payload BTC address', (80, 120))
        encrypted = xor_encrypt(content, key)
        final    = add_fake_pe_header(encrypted, ransomware_mode=True)
        level    = 'HIGH'
    elif choice == '2':
        base     = random.choice(['suspicious', 'packed', 'obfuscated', 'dropper'])
        filename = rand_filename(base, random.choice(['.dll', '.exe']))
        content  = rand_content('Suspicious tool data unknown origin medium risk', (50, 80))
        final    = add_fake_pe_header(b'HEUR_SUSP_PACKED:' + content, ransomware_mode=False)
        level    = 'MEDIUM'
    else:
        base     = random.choice(['helper', 'util', 'lib', 'module', 'plugin'])
        filename = rand_filename(base, '.dll')
        content  = rand_content('Normal safe application data benign content', (50, 80))
        final    = add_fake_pe_header(content, ransomware_mode=False)
        level    = 'LOW'

    filepath = os.path.join(WATCHED_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(final)

    icon = '🔴' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
    print(f"\n   {icon} Created: {filename} [{level}]")
    print(f"   Watch backend terminal for auto-scan!\n")


def show_menu():
    print(BANNER)
    print(f"📁 Watched folder: {WATCHED_DIR}\n")
    print("  1 — 🎯 MIXED Attack       (HIGH + MEDIUM + LOW — best for demo)")
    print("  2 — 🦠 FULL Ransomware    (all HIGH — tests auto-quarantine)")
    print("  3 — 📈 GRADUAL Escalation (LOW → MEDIUM → HIGH — APT sim)")
    print("  4 — ✅ BENIGN Files Only  (all LOW — tests false positive rate)")
    print("  5 — ⚡ Quick Single File  (one file — pick risk level)")
    print("  6 — 🗑️  Clean Watched Folder")
    print("  0 — Exit\n")
    return input("Enter choice: ").strip()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == 'attack':
            simulate_full_ransomware_attack(delay=1.5)
        elif arg == 'mixed':
            simulate_mixed_attack()
        elif arg == 'gradual':
            simulate_gradual_escalation()
        elif arg == 'benign':
            simulate_benign_files()
        elif arg == 'quick':
            quick_single_file()
        elif arg == 'clean':
            clean_watched_folder()
        sys.exit(0)

    while True:
        choice = show_menu()

        if choice == '1':
            delay = input("Delay between files in seconds (default 1.5): ").strip()
            delay = float(delay) if delay else 1.5
            simulate_mixed_attack(delay=delay)

        elif choice == '2':
            delay = input("Delay between files in seconds (default 2): ").strip()
            delay = float(delay) if delay else 2.0
            simulate_full_ransomware_attack(delay=delay)

        elif choice == '3':
            delay = input("Delay between stages in seconds (default 2): ").strip()
            delay = float(delay) if delay else 2.0
            simulate_gradual_escalation(delay=delay)

        elif choice == '4':
            count = input("How many benign files (default 5): ").strip()
            count = int(count) if count else 5
            simulate_benign_files(count=count)

        elif choice == '5':
            quick_single_file()

        elif choice == '6':
            clean_watched_folder()

        elif choice == '0':
            print("\nExiting simulator...\n")
            break

        else:
            print("\n   Invalid choice\n")

        input("Press Enter to continue...")

"""
Honeypot System for CyberDefense-AI
Creates and ACTIVELY MONITORS decoy files that should never be legitimately accessed.
Uses watchdog filesystem watcher — any READ, WRITE, or OPEN triggers an alert.
All honeypot files contain clearly fake/synthetic data.
"""
import os
import json
import hashlib
import threading
from datetime import datetime
from pathlib import Path

HONEYPOT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'lab', 'honeypot')
HONEYPOT_LOG = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'lab', 'honeypot_log.json')

# Decoy files with synthetic content — clearly fake
HONEYPOT_FILES = {
    'financial_report_Q4.xlsx': (
        b'[FAKE HONEYPOT DATA]\nQ4 Revenue: $0\nEmployee Count: 0\n'
        b'THIS FILE IS A CYBERSECURITY DECOY - NOT REAL FINANCIAL DATA\n'
    ),
    'employee_data.xlsx': (
        b'[FAKE HONEYPOT DATA]\nName,Department,Salary\n'
        b'HONEYPOT_USER_A,DECOY,0\nHONEYPOT_USER_B,DECOY,0\n'
        b'THIS FILE IS A CYBERSECURITY DECOY - NOT REAL EMPLOYEE DATA\n'
    ),
    'passwords.txt': (
        b'[FAKE HONEYPOT DATA]\n'
        b'admin:HONEYPOT_FAKE_PASSWORD_DO_NOT_USE\n'
        b'root:HONEYPOT_FAKE_PASSWORD_DO_NOT_USE\n'
        b'THIS FILE IS A CYBERSECURITY DECOY - NOT REAL CREDENTIALS\n'
    ),
    'backup.zip': (
        b'[FAKE HONEYPOT DATA]\n'
        b'PK\x03\x04FAKE_BACKUP_HONEYPOT_FILE\n'
        b'THIS FILE IS A CYBERSECURITY DECOY - NOT REAL BACKUP DATA\n'
    ),
    'credentials.db': (
        b'[FAKE HONEYPOT DATA]\nSQLite format 3 - HONEYPOT\n'
        b'username|password_hash\nhoneypot_user|FAKE_HASH_0000\n'
        b'THIS FILE IS A CYBERSECURITY DECOY - NOT REAL DATABASE\n'
    ),
    'ssh_private_key.pem': (
        b'-----BEGIN FAKE RSA PRIVATE KEY-----\n'
        b'THIS IS A HONEYPOT DECOY FILE\n'
        b'NOT A REAL PRIVATE KEY - CYBERSECURITY SIMULATION\n'
        b'MIIFakeHoneypotKeyDataNotRealDoNotUseThisFile0000000000000000000\n'
        b'-----END FAKE RSA PRIVATE KEY-----\n'
    ),
    'database_backup.sql': (
        b'-- HONEYPOT DECOY DATABASE DUMP\n'
        b'-- THIS IS FAKE DATA FOR CYBERSECURITY SIMULATION\n'
        b'CREATE TABLE fake_users (id INT, username TEXT, password TEXT);\n'
        b"INSERT INTO fake_users VALUES (1, 'honeypot', 'FAKE_HASH');\n"
    ),
}

_lock = threading.Lock()
_access_log: list = []
_trigger_callbacks: list = []
_watcher_active = False


def setup_honeypot() -> bool:
    """Create honeypot directory and all decoy files. Idempotent."""
    try:
        os.makedirs(HONEYPOT_DIR, exist_ok=True)
        for filename, content in HONEYPOT_FILES.items():
            path = os.path.join(HONEYPOT_DIR, filename)
            if not os.path.exists(path):
                with open(path, 'wb') as f:
                    f.write(content)
        print(f"🍯 Honeypot initialized: {HONEYPOT_DIR} ({len(HONEYPOT_FILES)} decoy files)")
        return True
    except Exception as e:
        print(f"⚠️  Honeypot setup failed: {e}")
        return False


def start_honeypot_watcher() -> bool:
    """
    Start active filesystem watcher on honeypot directory.
    Any access (read, write, open, delete) to a decoy file triggers an alert.
    Uses watchdog — same library as the file monitor.
    """
    global _watcher_active
    if _watcher_active:
        return True

    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class HoneypotHandler(FileSystemEventHandler):
            def _handle(self, event, operation):
                if event.is_directory:
                    return
                fname = os.path.basename(event.src_path)
                if fname in HONEYPOT_FILES:
                    # Get process that accessed the file (best effort)
                    proc_name, proc_pid = _get_accessor_process(event.src_path)
                    record_trigger(
                        resource=fname,
                        process_name=proc_name,
                        process_pid=proc_pid,
                        source_ip=None,   # filesystem access — no IP
                        operation=operation,
                    )

            def on_opened(self, event):   self._handle(event, 'OPEN')
            def on_accessed(self, event): self._handle(event, 'READ')
            def on_modified(self, event): self._handle(event, 'WRITE')
            def on_created(self, event):  self._handle(event, 'CREATE')
            def on_deleted(self, event):  self._handle(event, 'DELETE')
            # Fallback for watchdog versions that don't have on_opened
            def on_any_event(self, event):
                if hasattr(event, 'event_type') and event.event_type in ('opened', 'accessed'):
                    self._handle(event, event.event_type.upper())

        observer = Observer()
        handler  = HoneypotHandler()
        observer.schedule(handler, HONEYPOT_DIR, recursive=False)
        observer.start()

        _watcher_active = True
        print(f"🍯 Honeypot watcher ACTIVE — monitoring {HONEYPOT_DIR}")
        print(f"   Any access to decoy files will trigger an alert")
        return True

    except Exception as e:
        print(f"⚠️  Honeypot watcher failed to start: {e}")
        print(f"   Decoy files exist but filesystem access won't auto-detect")
        return False


def _get_accessor_process(filepath: str):
    """Try to find which process is accessing the file using psutil."""
    try:
        import psutil
        fname = os.path.basename(filepath)
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                files = proc.info.get('open_files') or []
                for f in files:
                    if fname in f.path:
                        return proc.info['name'], proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return 'Unknown', None


def get_watcher_status() -> dict:
    return {
        'active':      _watcher_active,
        'directory':   HONEYPOT_DIR,
        'file_count':  len(HONEYPOT_FILES),
        'trigger_count': get_trigger_count(),
    }


def setup_honeypot() -> bool:
    """Create honeypot directory and all decoy files. Idempotent."""
    try:
        os.makedirs(HONEYPOT_DIR, exist_ok=True)
        for filename, content in HONEYPOT_FILES.items():
            path = os.path.join(HONEYPOT_DIR, filename)
            if not os.path.exists(path):
                with open(path, 'wb') as f:
                    f.write(content)
        print(f"🍯 Honeypot initialized: {HONEYPOT_DIR} ({len(HONEYPOT_FILES)} decoy files)")
        return True
    except Exception as e:
        print(f"⚠️  Honeypot setup failed: {e}")
        return False


def get_honeypot_files() -> list:
    """Return list of honeypot file names and their SHA-256 hashes."""
    files = []
    for filename in HONEYPOT_FILES:
        path = os.path.join(HONEYPOT_DIR, filename)
        if os.path.exists(path):
            with open(path, 'rb') as f:
                data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            files.append({
                'name':     filename,
                'path':     path,
                'sha256':   sha256,
                'size':     os.path.getsize(path),
                'is_decoy': True,
            })
    return files


def record_trigger(
    resource: str,
    process_name: str = None,
    process_pid: int = None,
    source_ip: str = None,
    operation: str = 'READ',
    scenario_id: str = None,
) -> dict:
    """Record a honeypot access event and fire any registered callbacks."""
    now = datetime.utcnow().isoformat()
    event_id = hashlib.sha256(f'{resource}{now}{process_pid}'.encode()).hexdigest()[:16]

    entry = {
        'event_id':     event_id,
        'timestamp':    now,
        'resource':     resource,
        'operation':    operation,
        'process_name': process_name or 'Unknown',
        'process_pid':  process_pid,
        'source_ip':    source_ip,
        'scenario_id':  scenario_id,
        'triggered':    True,
    }

    with _lock:
        _access_log.append(entry)
        if len(_access_log) > 500:
            _access_log.pop(0)

    # Persist
    _save_log(entry)

    # Fire callbacks (e.g. to emit a WebSocket event)
    for cb in _trigger_callbacks:
        try:
            cb(entry)
        except Exception:
            pass

    print(f"🍯 HONEYPOT TRIGGERED: {resource} by {process_name or 'Unknown'} (PID {process_pid})")
    return entry


def register_callback(fn):
    """Register a function to be called whenever a honeypot is triggered."""
    _trigger_callbacks.append(fn)


def get_recent_triggers(limit: int = 50) -> list:
    with _lock:
        return list(reversed(_access_log[-limit:]))


def get_trigger_count() -> int:
    with _lock:
        return len(_access_log)


def _save_log(entry: dict):
    try:
        logs = _load_log()
        logs.append(entry)
        os.makedirs(os.path.dirname(HONEYPOT_LOG), exist_ok=True)
        with open(HONEYPOT_LOG, 'w') as f:
            json.dump(logs[-1000:], f, indent=2)
    except Exception:
        pass


def _load_log() -> list:
    try:
        if os.path.exists(HONEYPOT_LOG):
            with open(HONEYPOT_LOG) as f:
                return json.load(f)
    except Exception:
        pass
    return []


def load_persisted_triggers() -> list:
    """Load triggers from disk on startup."""
    entries = _load_log()
    with _lock:
        _access_log.extend(entries[-500:])
    return entries


def is_honeypot_file(path: str) -> bool:
    """Check if a given path is a honeypot resource."""
    name = os.path.basename(path)
    return name in HONEYPOT_FILES

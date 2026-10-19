import os
import sys
import json
import hashlib
import ipaddress
import sqlite3
import threading
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np

# Fix Windows console encoding for emoji support
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / '.env')

import jwt
from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from utils.db import init_db, save_threat
from utils.db import get_user, verify_user, get_all_users, create_user, delete_user, change_password
from utils.db import log_audit, get_audit_logs, update_threat_summary, get_threats_csv
from models.threat_scorer import predict

app = Flask(__name__)
app.config['SECRET_KEY']       = os.getenv('SECRET_KEY', 'cyberdefense-secret')
app.config['THREAT_THRESHOLD'] = 70
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=False,
    allow_upgrades=False,
    ping_interval=25,
    ping_timeout=60,
)

init_db()

# ── Rate Limiting ─────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])
    LIMITER_AVAILABLE = True
    print("[OK] Rate limiter ready")
except Exception:
    limiter = None
    LIMITER_AVAILABLE = False


def rate_limit(rule: str):
    """Return active limiter decorator when available, otherwise no-op."""
    if LIMITER_AVAILABLE and limiter is not None:
        return limiter.limit(rule)

    def _noop(func):
        return func

    return _noop

# ── Webhook ───────────────────────────────────────────────
try:
    from utils.webhooks import send_webhook_alert
    WEBHOOK_AVAILABLE = bool(os.getenv('WEBHOOK_URL', '').strip())
except Exception:
    send_webhook_alert = None
    WEBHOOK_AVAILABLE  = False


# ── MITRE ATT&CK Mapping ──────────────────────────────────
def map_mitre(features: dict, prediction: str) -> list:
    """Return list of relevant MITRE ATT&CK technique dicts based on features."""
    tactics = []
    score = features.get('BitcoinAddresses', 0)
    sections = features.get('NumberOfSections', 0)
    dll_chars = features.get('DllCharacteristics', 0)
    stack = features.get('SizeOfStackReserve', 1048576)
    resource = features.get('ResourceSize', 0)
    iat = features.get('IatVRA', 0)

    if prediction == 'Ransomware' or score > 0:
        tactics.append({'id': 'T1486', 'name': 'Data Encrypted for Impact',
                        'tactic': 'Impact', 'reason': 'Bitcoin address embedded',
                        'url': 'https://attack.mitre.org/techniques/T1486/'})
    if dll_chars == 0:
        tactics.append({'id': 'T1027', 'name': 'Obfuscated Files or Information',
                        'tactic': 'Defense Evasion', 'reason': 'No DLL security features (no ASLR/DEP/CFG)',
                        'url': 'https://attack.mitre.org/techniques/T1027/'})
    if sections > 5 or sections < 2:
        tactics.append({'id': 'T1027.002', 'name': 'Software Packing',
                        'tactic': 'Defense Evasion', 'reason': f'Unusual section count ({sections})',
                        'url': 'https://attack.mitre.org/techniques/T1027/002/'})
    if stack < 500000:
        tactics.append({'id': 'T1055', 'name': 'Process Injection',
                        'tactic': 'Privilege Escalation', 'reason': 'Small stack reserve suggests injector',
                        'url': 'https://attack.mitre.org/techniques/T1055/'})
    if iat == 0:
        tactics.append({'id': 'T1129', 'name': 'Shared Modules',
                        'tactic': 'Execution', 'reason': 'Empty IAT — dynamic import resolution',
                        'url': 'https://attack.mitre.org/techniques/T1129/'})
    if resource == 0:
        tactics.append({'id': 'T1564', 'name': 'Hide Artifacts',
                        'tactic': 'Defense Evasion', 'reason': 'No resources section',
                        'url': 'https://attack.mitre.org/techniques/T1564/'})
    if prediction in ('Ransomware', 'Suspicious'):
        tactics.append({'id': 'T1490', 'name': 'Inhibit System Recovery',
                        'tactic': 'Impact', 'reason': 'Ransomware/suspicious file may delete shadow copies',
                        'url': 'https://attack.mitre.org/techniques/T1490/'})
    # Always add at least one baseline technique for any PE file
    if not tactics:
        tactics.append({'id': 'T1106', 'name': 'Native API',
                        'tactic': 'Execution', 'reason': 'PE file uses native Windows API calls',
                        'url': 'https://attack.mitre.org/techniques/T1106/'})
    return tactics[:5]  # cap at 5 most relevant

# ── Blockchain ────────────────────────────────────────────
try:
    from utils.blockchain_logger import logger as bc_logger
    from utils.blockchain_logger import log_threat as blockchain_log
    from utils.blockchain_logger import verify_hash as blockchain_verify_hash
    from utils.blockchain_logger import get_all_logs as blockchain_get_logs
    print(f"[CHAIN] Blockchain mode : {bc_logger.mode}")
    if bc_logger.mode == 'core_testnet2':
        print(f"[OK] Blockchain ready : {os.getenv('CONTRACT_ADDRESS')}")
    else:
        print(f"[INFO] Blockchain      : local simulation")
except Exception as e:
    print(f"[WARN] Blockchain init failed: {e}")
    bc_logger              = None
    blockchain_log         = None
    blockchain_verify_hash = None
    blockchain_get_logs    = None

# ── Email ─────────────────────────────────────────────────
try:
    from utils.email_alerts import send_high_threat_alert, send_system_startup_email
    EMAIL_AVAILABLE = True
    print("[OK] Email alerts ready")
except Exception as e:
    EMAIL_AVAILABLE           = False
    send_high_threat_alert    = None
    send_system_startup_email = None
    print(f"[WARN] Email init failed: {e}")

if EMAIL_AVAILABLE and send_system_startup_email:
    threading.Thread(target=send_system_startup_email, daemon=True).start()

# ── Users ─────────────────────────────────────────────────
# Users are now persisted in SQLite via utils/db.py
# Default accounts (admin/admin123, analyst/analyst123) are seeded on first run


# ── Token Helpers ─────────────────────────────────────────
def verify_token(req):
    auth = req.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    try:
        return jwt.decode(
            auth[7:], app.config['SECRET_KEY'], algorithms=['HS256']
        )
    except Exception:
        return None


def admin_only(req):
    user = verify_token(req)
    if not user or user.get('role') != 'admin':
        return None
    return user


# ═════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════

@app.route('/api/verify-token', methods=['GET', 'OPTIONS'])
def verify_token_route():
    """
    Called by frontend on every page load.
    Verifies JWT is valid and not expired.
    OPTIONS method handles CORS preflight check.
    """
    # CORS preflight — must return 200 or browser blocks the real request
    if request.method == 'OPTIONS':
        return jsonify({'ok': True}), 200

    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Token missing'}), 401

    try:
        data = jwt.decode(
            auth[7:],
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return jsonify({
            'valid':    True,
            'username': data.get('username'),
            'role':     data.get('role')
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    user     = verify_user(username, password)
    if not user:
        log_audit(username, 'LOGIN_FAILED', f'IP: {request.remote_addr}')
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({
        'username': username,
        'role':     user['role'],
        'exp':      datetime.utcnow() + timedelta(hours=8)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    log_audit(username, 'LOGIN_SUCCESS', f'Role: {user["role"]} | IP: {request.remote_addr}')
    return jsonify({'token': token, 'role': user['role'], 'username': username})


# ═════════════════════════════════════════════════════════
# PREDICTION
# ═════════════════════════════════════════════════════════

@app.route('/api/predict', methods=['POST'])
def predict_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data     = request.get_json()
    features = data.get('features', {})
    result   = predict(features)

    hash_data = {
        'prediction':   result['prediction'],
        'threat_score': result['threat_score'],
        'risk_level':   result['risk_level'],
        'timestamp':    result['timestamp']
    }
    result['hash'] = hashlib.sha256(
        json.dumps(hash_data, sort_keys=True).encode()
    ).hexdigest()

    # ── MITRE ATT&CK Mapping ──────────────────────────────
    mitre_tactics = map_mitre(features, result['prediction'])
    result['mitre_tactics'] = mitre_tactics
    mitre_str = ', '.join(f"{t['id']} {t['name']}" for t in mitre_tactics)

    threat_id = None
    save_threat({
        'file_name':       features.get('file_name', 'unknown'),
        'features':        json.dumps(features),
        'prediction':      result['prediction'],
        'threat_score':    result['threat_score'],
        'blockchain_hash': result['hash'],
        'timestamp':       result['timestamp'],
        'mitre_tactics':   mitre_str
    })
    # Grab the ID of the just-inserted row
    try:
        import sqlite3 as _sq
        _conn = _sq.connect('cyberdefense.db')
        threat_id = _conn.execute('SELECT MAX(id) FROM threats').fetchone()[0]
        _conn.close()
    except Exception:
        pass

    log_audit(user.get('username'), 'SCAN',
              f'{features.get("file_name","?")} → {result["prediction"]} ({result["threat_score"]})')

    if blockchain_log:
        try:
            bc_result = blockchain_log({
                'threat_score': result['threat_score'],
                'prediction':   result['prediction'],
                'hash':         result['hash'],
                'timestamp':    result['timestamp']
            })
            result['blockchain'] = {
                'mode':       bc_result.get('mode'),
                'tx_hash':    bc_result.get('tx_hash'),
                'block':      bc_result.get('block'),
                'explorer':   bc_result.get('explorer'),
                'alert_hash': bc_result.get('alert_hash')
            }
            print(f"⛓  Blockchain logged — mode: {bc_result.get('mode')}")
        except Exception as e:
            print(f"[WARN] Blockchain log failed: {e}")

    threshold = app.config.get('THREAT_THRESHOLD', 70)
    if result['threat_score'] > 30:  # generate AI summary for MEDIUM and HIGH
        full_data = {**result, 'file_name': features.get('file_name', 'unknown'), 'mitre_str': mitre_str}

        if result['threat_score'] > threshold:
            if EMAIL_AVAILABLE and send_high_threat_alert:
                threading.Thread(target=send_high_threat_alert, args=(full_data,), daemon=True).start()

            if WEBHOOK_AVAILABLE and send_webhook_alert:
                threading.Thread(target=send_webhook_alert, args=(full_data,), daemon=True).start()

        if result['threat_score'] > threshold:
            socketio.emit('high_threat_alert', {
                'prediction':   result['prediction'],
                'threat_score': result['threat_score'],
                'risk_level':   result['risk_level'],
                'timestamp':    result['timestamp']
            })
            print(f"🚨 HIGH THREAT ALERT — score: {result['threat_score']}")

        # ── Emit file_scanned for every scan (populates SOC Live Feed) ───
        socketio.emit('file_scanned', {
            'file_name':    features.get('file_name', 'unknown'),
            'prediction':   result['prediction'],
            'threat_score': result['threat_score'],
            'risk_level':   result['risk_level'],
            'timestamp':    result['timestamp']
        })

        # ── AI Incident Summary (async) ───────────────────
        if threat_id:
            def _gen_summary(tid, tdata):
                try:
                    from utils.chatbot import chat as ai_chat
                    prompt = (
                        f"Write a 3-sentence incident summary for a SOC analyst. "
                        f"File: {tdata.get('file_name','unknown')}. "
                        f"Prediction: {tdata['prediction']}. "
                        f"Threat score: {tdata['threat_score']}. "
                        f"MITRE tactics: {tdata.get('mitre_str','')}. "
                        f"Keep it concise and professional."
                    )
                    summary = ai_chat(prompt, context={}, history=[])
                    update_threat_summary(tid, summary)
                except Exception as ex:
                    print(f"[WARN] AI summary failed: {ex}")
            threading.Thread(target=_gen_summary, args=(threat_id, full_data), daemon=True).start()

    return jsonify(result)


# ═════════════════════════════════════════════════════════
# PE FILE UPLOAD SCAN
# ═════════════════════════════════════════════════════════

@app.route('/api/upload-scan', methods=['POST'])
def upload_scan():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    f         = request.files['file']
    file_name = f.filename or 'uploaded_file'
    ext       = os.path.splitext(file_name)[1].lower()

    # Save to temp file
    suffix = ext if ext else '.bin'
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        from models.file_monitor import extract_pe_features
        features = extract_pe_features(tmp_path)
        if not features:
            return jsonify({'error': 'Could not extract PE features from file'}), 422

        features['file_name'] = file_name
        result = predict(features)

        hash_data = {
            'prediction':   result['prediction'],
            'threat_score': result['threat_score'],
            'risk_level':   result['risk_level'],
            'timestamp':    result['timestamp']
        }
        result['hash'] = hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()

        mitre_tactics = map_mitre(features, result['prediction'])
        result['mitre_tactics'] = mitre_tactics
        mitre_str = ', '.join(f"{t['id']} {t['name']}" for t in mitre_tactics)

        save_threat({
            'file_name':       file_name,
            'features':        json.dumps(features),
            'prediction':      result['prediction'],
            'threat_score':    result['threat_score'],
            'blockchain_hash': result['hash'],
            'timestamp':       result['timestamp'],
            'mitre_tactics':   mitre_str
        })

        log_audit(user.get('username'), 'UPLOAD_SCAN',
                  f'{file_name} → {result["prediction"]} ({result["threat_score"]})')

        if blockchain_log:
            try:
                bc_result = blockchain_log({
                    'threat_score': result['threat_score'],
                    'prediction':   result['prediction'],
                    'hash':         result['hash'],
                    'timestamp':    result['timestamp']
                })
                result['blockchain'] = {
                    'mode':       bc_result.get('mode'),
                    'tx_hash':    bc_result.get('tx_hash'),
                    'block':      bc_result.get('block'),
                    'explorer':   bc_result.get('explorer'),
                    'alert_hash': bc_result.get('alert_hash')
                }
            except Exception:
                pass

        threshold = app.config.get('THREAT_THRESHOLD', 70)
        if result['threat_score'] > threshold:
            if EMAIL_AVAILABLE and send_high_threat_alert:
                threading.Thread(target=send_high_threat_alert,
                                 args=({**result, 'file_name': file_name},), daemon=True).start()
            if WEBHOOK_AVAILABLE and send_webhook_alert:
                threading.Thread(target=send_webhook_alert,
                                 args=({**result, 'file_name': file_name},), daemon=True).start()
            socketio.emit('high_threat_alert', {
                'prediction':   result['prediction'],
                'threat_score': result['threat_score'],
                'risk_level':   result['risk_level'],
                'timestamp':    result['timestamp']
            })

        return jsonify(result)

    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


# ═════════════════════════════════════════════════════════
# DASHBOARD
# ═════════════════════════════════════════════════════════

@app.route('/api/threats', methods=['GET'])
def get_threats():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_all_threats
    return jsonify(get_all_threats())


@app.route('/api/stats', methods=['GET'])
def get_stats():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_stats
    return jsonify(get_stats())


@app.route('/api/shap', methods=['GET'])
def get_shap():
    shap_path = os.path.join('models', 'shap_values.json')
    if os.path.exists(shap_path):
        with open(shap_path) as f:
            return jsonify(json.load(f))
    return jsonify({})


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status':          'ok',
        'timestamp':       datetime.utcnow().isoformat(),
        'blockchain_mode': bc_logger.mode if bc_logger else 'unavailable',
        'email_enabled':   EMAIL_AVAILABLE
    })


@app.route('/api/system/health', methods=['GET'])
def system_health():
    """Real component health check — no dummy values."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    from models.network_monitor import get_monitor
    from utils.honeypot import get_watcher_status

    nm = get_monitor()
    ws = get_watcher_status()

    # ML model status — check if scorer models are loaded
    ml_loaded = False
    ml_detail = 'Not loaded'
    try:
        from models.network_scorer import get_scorer_info
        info = get_scorer_info()
        ml_loaded = info.get('loaded', False)
        ml_detail = info.get('detail', 'Unknown')
    except Exception as _e:
        ml_detail = str(_e)

    # File monitor — check if the daemon thread is alive
    import sys as _sys
    _mod = _sys.modules[__name__] if __name__ in _sys.modules else None
    fm_thread = globals().get('monitor_thread')
    fm_alive = fm_thread.is_alive() if fm_thread else False

    # Network monitor
    nm_mode   = (nm.capture_mode if nm else 'unavailable') if nm else 'unavailable'
    nm_online = nm is not None

    # DB check
    db_ok = False
    try:
        from utils.db import get_db
        conn = get_db()
        conn.execute('SELECT 1')
        db_ok = True
    except Exception:
        pass

    # WebSocket — socketio is always running if app started
    ws_ok = True

    # Blockchain
    bc_ok   = bc_logger is not None
    bc_mode = bc_logger.mode if bc_logger else 'unavailable'

    # IP intel APIs — check .env keys presence (not actual network call)
    abuseipdb_ok  = bool(os.getenv('ABUSEIPDB_KEY', ''))
    shodan_ok     = bool(os.getenv('SHODAN_KEY', ''))
    virustotal_ok = bool(os.getenv('VIRUSTOTAL_KEY', ''))

    return jsonify({
        'timestamp': datetime.utcnow().isoformat(),
        'components': {
            'database':        {'ok': db_ok,      'detail': 'SQLite connected' if db_ok else 'Error'},
            'ml_model':        {'ok': ml_loaded,   'detail': ml_detail},
            'file_monitor':    {'ok': fm_alive,    'detail': 'Watching' if fm_alive else 'Thread not running'},
            'network_monitor': {'ok': nm_online,   'detail': nm_mode},
            'honeypot':        {'ok': ws['active'], 'detail': f"Watcher {'active' if ws['active'] else 'inactive'} — {ws.get('trigger_count', 0)} triggers"},
            'blockchain':      {'ok': bc_ok,       'detail': bc_mode},
            'websocket':       {'ok': ws_ok,       'detail': 'Running'},
            'abuseipdb':       {'ok': abuseipdb_ok,'detail': 'Key configured' if abuseipdb_ok else 'No API key'},
            'shodan':          {'ok': shodan_ok,   'detail': 'Key configured' if shodan_ok else 'No API key'},
            'virustotal':      {'ok': virustotal_ok,'detail': 'Key configured' if virustotal_ok else 'No API key'},
        }
    })


# ═════════════════════════════════════════════════════════
# PDF REPORT
# ═════════════════════════════════════════════════════════

@app.route('/api/report', methods=['POST'])
def generate_report_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.report_generator import generate_report
    data     = request.get_json()
    filepath = generate_report(data)
    filename = os.path.basename(filepath)
    log_audit(user.get('username'), 'REPORT_DOWNLOAD', filename)
    return send_file(
        filepath, as_attachment=True,
        download_name=filename, mimetype='application/pdf'
    )


# ═════════════════════════════════════════════════════════
# CSV EXPORT
# ═════════════════════════════════════════════════════════

@app.route('/api/threats/export/csv', methods=['GET'])
def export_threats_csv():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from flask import Response
    csv_data = get_threats_csv()
    log_audit(user.get('username'), 'CSV_EXPORT', 'All threats exported')
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=threats_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'}
    )


# ═════════════════════════════════════════════════════════
# AUDIT LOG
# ═════════════════════════════════════════════════════════

@app.route('/api/audit-log', methods=['GET'])
def get_audit_log_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    limit = int(request.args.get('limit', 500))
    return jsonify(get_audit_logs(limit))


# ═════════════════════════════════════════════════════════
# BLOCKCHAIN
# ═════════════════════════════════════════════════════════

@app.route('/api/blockchain/log', methods=['POST'])
def blockchain_log_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not blockchain_log:
        return jsonify({'error': 'Blockchain not available'}), 503
    data   = request.get_json()
    result = blockchain_log(data)
    return jsonify(result)


@app.route('/api/blockchain/verify', methods=['POST'])
def blockchain_verify_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not blockchain_verify_hash:
        return jsonify({'error': 'Blockchain not available'}), 503
    data   = request.get_json()
    result = blockchain_verify_hash(data.get('hash', ''))
    return jsonify(result)


@app.route('/api/blockchain/logs', methods=['GET'])
def blockchain_logs_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not blockchain_get_logs:
        return jsonify([])
    return jsonify(blockchain_get_logs())


@app.route('/api/blockchain/status', methods=['GET'])
def blockchain_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'mode':          bc_logger.mode if bc_logger else 'unavailable',
        'contract':      os.getenv('CONTRACT_ADDRESS', ''),
        'rpc':           os.getenv('ETH_RPC_URL', ''),
        'chain_id':      os.getenv('CHAIN_ID', ''),
        'wallet':        bc_logger.account.address if bc_logger and bc_logger.account else '',
        'explorer_base': 'https://scan.test2.btcs.network'
    })


# ═════════════════════════════════════════════════════════
# EMAIL
# ═════════════════════════════════════════════════════════

@app.route('/api/email/status', methods=['GET'])
def email_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'enabled':  os.getenv('EMAIL_ENABLED', 'false'),
        'sender':   os.getenv('EMAIL_SENDER', ''),
        'receiver': os.getenv('EMAIL_RECEIVER', ''),
        'ready':    EMAIL_AVAILABLE
    })


@app.route('/api/email/test', methods=['POST'])
def email_test():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'error': 'Email test disabled - only real threat alerts are sent'}), 403


# ═════════════════════════════════════════════════════════
# ADMIN
# ═════════════════════════════════════════════════════════

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    return jsonify(get_all_users())


@app.route('/api/admin/users', methods=['POST'])
def admin_add_user():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role     = data.get('role', 'analyst')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if not create_user(username, password, role):
        return jsonify({'error': 'User already exists'}), 409
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'USER_CREATED', f'{username} ({role})')
    print(f"👤 Admin added user: {username} ({role})")
    return jsonify({'status': 'User created', 'username': username})


@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete_user(username):
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    if username == 'admin':
        return jsonify({'error': 'Cannot delete admin'}), 400
    if not get_user(username):
        return jsonify({'error': 'User not found'}), 404
    delete_user(username)
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'USER_DELETED', username)
    print(f"👤 Admin deleted user: {username}")
    return jsonify({'status': 'User deleted'})


@app.route('/api/admin/users/<username>/password', methods=['PUT'])
def admin_change_password(username):
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    data     = request.get_json()
    password = data.get('password', '').strip()
    if not password:
        return jsonify({'error': 'Password required'}), 400
    if not get_user(username):
        return jsonify({'error': 'User not found'}), 404
    change_password(username, password)
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'PASSWORD_CHANGED', username)
    print(f"👤 Password changed for: {username}")
    return jsonify({'status': 'Password updated'})


@app.route('/api/admin/quarantine', methods=['GET'])
def admin_get_quarantine():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    log_path = os.path.join(os.path.dirname(__file__), 'quarantine', 'quarantine_log.json')
    if not os.path.exists(log_path):
        return jsonify([])
    with open(log_path) as f:
        try:
            return jsonify(json.load(f))
        except Exception:
            return jsonify([])


@app.route('/api/admin/quarantine/clear', methods=['DELETE'])
def admin_clear_quarantine():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    cleared = 0
    if os.path.exists(quarantine_dir):
        for f in os.listdir(quarantine_dir):
            if f != 'quarantine_log.json':
                try:
                    os.remove(os.path.join(quarantine_dir, f))
                    cleared += 1
                except Exception:
                    pass
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'QUARANTINE_CLEARED', f'{cleared} files removed')
    print(f"[QUARANTINE] Cleared: {cleared} files")
    return jsonify({'status': f'Cleared {cleared} files'})


@app.route('/api/admin/system', methods=['GET'])
def admin_system_info():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    import platform
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    q_files = len([
        f for f in os.listdir(quarantine_dir)
        if f != 'quarantine_log.json'
    ]) if os.path.exists(quarantine_dir) else 0
    bc_logs = len(blockchain_get_logs()) if blockchain_get_logs else 0
    return jsonify({
        'platform':         platform.system(),
        'python':           platform.python_version(),
        'blockchain_mode':  bc_logger.mode if bc_logger else 'unavailable',
        'email_enabled':    os.getenv('EMAIL_ENABLED', 'false'),
        'webhook_enabled':  WEBHOOK_AVAILABLE,
        'rate_limiting':    LIMITER_AVAILABLE,
        'quarantine_files': q_files,
        'blockchain_logs':  bc_logs,
        'users_count':      len(get_all_users()),
        'contract':         os.getenv('CONTRACT_ADDRESS', 'N/A'),
        'uptime':           datetime.utcnow().isoformat()
    })


@app.route('/api/admin/threats/clear', methods=['DELETE'])
def admin_clear_threats():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    try:
        db_path = os.path.join(os.path.dirname(__file__), 'cyberdefense.db')
        conn    = sqlite3.connect(db_path)
        conn.execute('DELETE FROM threats')
        conn.commit()
        conn.close()
        admin = verify_token(request)
        log_audit(admin.get('username') if admin else 'admin', 'THREATS_CLEARED', 'All threat records deleted')
        print("[DB] Threat database cleared")
        return jsonify({'status': 'Threat database cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/settings', methods=['GET'])
def admin_get_settings():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    return jsonify({
        'threat_threshold': app.config.get('THREAT_THRESHOLD', 70),
        'blockchain_mode':  bc_logger.mode if bc_logger else 'unavailable',
        'email_enabled':    EMAIL_AVAILABLE,
    })


@app.route('/api/admin/settings', methods=['POST'])
def admin_update_settings():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    data      = request.get_json()
    threshold = data.get('threat_threshold')
    if threshold is not None:
        app.config['THREAT_THRESHOLD'] = int(threshold)
        admin = verify_token(request)
        log_audit(admin.get('username') if admin else 'admin', 'SETTINGS_CHANGED', f'threshold={threshold}')
        print(f"[CONFIG] Threat threshold updated: {threshold}")
    return jsonify({
        'status':    'Settings updated',
        'threshold': app.config.get('THREAT_THRESHOLD', 70)
    })


# ═════════════════════════════════════════════════════════
# AI CHATBOT
# ═════════════════════════════════════════════════════════

@app.route('/api/chat', methods=['POST'])
def chat_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.chatbot import chat as ai_chat
    from utils.db import get_stats, get_all_threats, get_audit_logs, get_all_users
    body    = request.get_json()
    message = body.get('message', '').strip()
    history = body.get('history', [])

    if not message:
        return jsonify({'error': 'Message required'}), 400

    # ── Build rich live context server-side ───────────────
    try:
        db_stats   = get_stats()
        db_threats = get_all_threats()
        audit_logs = get_audit_logs(200)
        all_users  = get_all_users()

        # Failed login count (last 24 h worth)
        failed_logins = sum(1 for e in audit_logs if e.get('action') == 'LOGIN_FAILED')
        recent_logins = [e for e in audit_logs if e.get('action') in ('LOGIN_SUCCESS', 'LOGIN_FAILED')][:10]

        # Quarantine info
        quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
        q_log_path     = os.path.join(quarantine_dir, 'quarantine_log.json')
        quarantine_log = []
        if os.path.exists(q_log_path):
            try:
                with open(q_log_path) as _f:
                    quarantine_log = json.load(_f)
            except Exception:
                pass
        q_files = len([f for f in os.listdir(quarantine_dir)
                       if f != 'quarantine_log.json']) if os.path.exists(quarantine_dir) else 0

        # Recent audit events (non-login)
        recent_audit = [e for e in audit_logs
                        if e.get('action') not in ('LOGIN_SUCCESS', 'LOGIN_FAILED')][:10]

        context = {
            'stats':          db_stats,
            'threats':        db_threats[:10],
            'failed_logins':  failed_logins,
            'recent_logins':  recent_logins,
            'quarantine_count': q_files,
            'quarantine_log': quarantine_log[:10],
            'recent_audit':   recent_audit,
            'users_count':    len(all_users),
            'users':          all_users,
            'blockchain_mode': bc_logger.mode if bc_logger else 'unavailable',
            'threat_threshold': app.config.get('THREAT_THRESHOLD', 70),
            'email_enabled':  EMAIL_AVAILABLE,
            'current_user':   user.get('username'),
            'current_role':   user.get('role'),
        }
    except Exception:
        context = body.get('context', {})

    try:
        reply = ai_chat(message, context=context, history=history)
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ═════════════════════════════════════════════════════════
# WEBSOCKET
# ═════════════════════════════════════════════════════════

@socketio.on('connect')
def on_connect():
    emit('connected', {'message': '🛡️ CyberDefense SOC connected'})
    print("[WS] Client connected via WebSocket")


@socketio.on('disconnect')
def on_disconnect():
    print("[WS] Client disconnected")


# ═════════════════════════════════════════════════════════
# FILE MONITOR
# ═════════════════════════════════════════════════════════

def start_file_monitor():
    try:
        import time
        from watchdog.observers import Observer
        from models.file_monitor import ThreatHandler, WATCHED_DIR, reset_token
        os.makedirs(WATCHED_DIR, exist_ok=True)
        print(f"[FILE MONITOR] Waiting for server...")
        time.sleep(3)
        reset_token()
        handler  = ThreatHandler()
        observer = Observer()
        observer.schedule(handler, WATCHED_DIR, recursive=False)
        observer.start()
        print(f"[FILE MONITOR] Started: {WATCHED_DIR}")
        # Scan files that were already in watched/ before the monitor started
        from models.file_monitor import scan_existing_files
        scan_existing_files()
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"[WARN] File monitor failed: {e}")

monitor_thread = threading.Thread(target=start_file_monitor, daemon=True)
monitor_thread.start()


# ═════════════════════════════════════════════════════════
# REAL-TIME TSHARK CAPTURE
# ═════════════════════════════════════════════════════════

# Global instances
_tshark_capture = None
_flow_extractor = None
_ml_predictor = None
_live_flows = []
_live_alerts = []
_attackers = {}
_live_packets = []
_first_packet_epoch = None
_verified_alert_last_seen = {}
_verified_alert_lock = threading.Lock()


def _normalize_ip_address(address):
    """Normalize IP literals for matching, excluding IPv6 interface scopes."""
    if not address:
        return ''
    value = str(address).split('%', 1)[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def init_realtime_capture():
    """Initialize real-time capture components"""
    global _tshark_capture, _flow_extractor
    
    try:
        from utils.tshark_capture import TSharkCapture
        from utils.flow_extractor import FlowExtractor
        from models.network_scorer import predict_flow, get_status
        
        _tshark_capture = TSharkCapture(socketio)
        _flow_extractor = FlowExtractor()
        model_status = get_status()
        if model_status.get('network_ids_loaded'):
            print("[OK] Trained network IDS loaded for real-time verification")
        else:
            print("[WARN] Trained network IDS unavailable; flow alerts will not be confirmed")
        
        # Start flow extractor with callback
        def on_flow_complete(features, flow):
            """Callback when a flow is complete"""
            global _live_flows, _live_alerts, _attackers
            
            # Get ML prediction
            prediction = predict_flow(features)
            model_name = prediction.get('model', 'not_loaded')
            confidence = float(prediction.get('confidence') or 0)
            predicted_class = str(prediction.get('prediction') or 'UNKNOWN').upper()
            is_model_available = (
                model_name in ('network_rf_dnn_ensemble', 'network_random_forest')
                and prediction.get('verified') is True
                and predicted_class != 'UNKNOWN'
            )
            is_attack = (
                is_model_available
                and prediction.get('verified') is True
                and prediction.get('is_attack') is True
                and predicted_class != 'BENIGN'
                and confidence >= 70.0
            )
            
            # Create flow record (convert numpy types to native Python types)
            flow_record = {
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': int(flow.src_port),
                'dst_port': int(flow.dst_port),
                'protocol': flow.protocol,
                'packets': int(flow.total_packets),
                'bytes': int(flow.total_bytes),
                'duration': float((flow.last_seen - flow.first_seen).total_seconds()),
                'prediction': predicted_class,
                'confidence': confidence,
                'is_anomaly': bool(prediction.get('is_anomaly', False)),
                'is_attack': is_attack,
                'is_verified': prediction.get('verified') is True and is_model_available,
                'model': model_name,
                'verification_status': 'confirmed_attack' if is_attack else (
                    'benign' if is_model_available and predicted_class == 'BENIGN' and confidence >= 70.0
                    else 'unverified'
                ),
                'risk_score': float(prediction.get('risk_score', 0)),
                'timestamp': flow.last_seen.isoformat(),
            }
            
            # Add to live flows
            _live_flows.append(flow_record)
            if len(_live_flows) > 10000:
                _live_flows = _live_flows[-10000:]
            
            # A flow is an attack only when the trained classifier confirms it.
            if is_attack:
                alert_key = (
                    flow.src_ip, flow.dst_ip, int(flow.src_port), int(flow.dst_port),
                    flow.protocol, predicted_class,
                )
                now = flow.last_seen
                with _verified_alert_lock:
                    previous_alert = _verified_alert_last_seen.get(alert_key)
                    if previous_alert and (now - previous_alert).total_seconds() < 60:
                        return
                    _verified_alert_last_seen[alert_key] = now
                    expired_alerts = [
                        key for key, seen_at in _verified_alert_last_seen.items()
                        if (now - seen_at).total_seconds() >= 300
                    ]
                    for key in expired_alerts:
                        _verified_alert_last_seen.pop(key, None)

                alert_id = hashlib.sha256(
                    f"{alert_key}:{now.isoformat()}".encode()
                ).hexdigest()[:20]
                alert = {
                    'id': f'alert_{alert_id}',
                    'attack_type': predicted_class,
                    'severity': 'HIGH' if confidence >= 85 else 'MEDIUM',
                    'attacker_ip': flow.src_ip,
                    'target_ip': flow.dst_ip,
                    'src_port': int(flow.src_port),
                    'dst_port': int(flow.dst_port),
                    'protocol': flow.protocol,
                    'timestamp': flow.last_seen.isoformat(),
                    'confidence': confidence,
                    'risk_score': float(prediction.get('risk_score', 0)),
                    'model': model_name,
                    'is_verified': True,
                    'verification': 'trained_network_ids',
                    'verification_status': 'confirmed_attack',
                    'prediction': predicted_class,
                    'features': {k: float(v) if isinstance(v, (int, float, np.number)) else v for k, v in features.items()},
                }
                
                _live_alerts.append(alert)
                if len(_live_alerts) > 1000:
                    _live_alerts = _live_alerts[-1000:]
                
                # Track attacker
                attacker_key = flow.src_ip
                if attacker_key not in _attackers:
                    _attackers[attacker_key] = {
                        'ip': flow.src_ip,
                        'first_seen': flow.first_seen.isoformat(),
                        'last_seen': flow.last_seen.isoformat(),
                        'attempts': 0,
                        'packets': 0,
                        'flows': 0,
                        'attack_types': set(),
                        'risk_score': 0,
                    }
                
                _attackers[attacker_key]['last_seen'] = flow.last_seen.isoformat()
                _attackers[attacker_key]['attempts'] += 1
                _attackers[attacker_key]['packets'] += flow.total_packets
                _attackers[attacker_key]['flows'] += 1
                _attackers[attacker_key]['attack_types'].add(predicted_class)
                _attackers[attacker_key]['risk_score'] = max(
                    _attackers[attacker_key]['risk_score'],
                    prediction.get('risk_score', 0)
                )
                
                # Emit via WebSocket
                socketio.emit('alert_created', alert)
                socketio.emit('network_alert', {
                    **alert,
                    'type': predicted_class,
                    'ip': flow.src_ip,
                    'src_ip': flow.src_ip,
                    'timestamp': flow.last_seen.isoformat(),
                    'description': (
                        f"Trained network IDS classified {predicted_class} "
                        f"with {confidence:.1f}% confidence"
                    ),
                })
                socketio.emit('attacker_update', {
                    'ip': flow.src_ip,
                    'attack_type': predicted_class,
                    'risk_score': prediction.get('risk_score'),
                })
                
                print(
                    f"[ML VERIFIED] {predicted_class} ({confidence:.1f}%) "
                    f"from {flow.src_ip} -> {flow.dst_ip}"
                )
            
        _flow_extractor.start(on_flow_complete)
        
        # Packet callback for TShark
        packet_batch = []
        packet_batch_lock = threading.Lock()
        last_packet_emit = [0.0]
        max_pending_packets = 500

        def on_packet(packet):
            """Callback for each captured packet"""
            global _live_packets, _first_packet_epoch
            _flow_extractor.add_packet(packet)
            epoch = packet.get('frame.time_epoch')
            if epoch and _first_packet_epoch is None:
                _first_packet_epoch = epoch
            protocol = packet.get('_ws.col.Protocol') or (
                'DNS' if packet.get('dns.qry.name') else
                'QUIC' if packet.get('quic.long.packet_type') else
                'TLS' if packet.get('tls.record.content_type') else
                'TCP' if packet.get('tcp.srcport') else
                ('UDP' if packet.get('udp.srcport') else packet.get('ip.proto', 'IP'))
            )
            info = packet.get('_ws.col.Info', '')
            if not info:
                if packet.get('dns.qry.name'):
                    info = f"Standard query {packet['dns.qry.name']}"
                elif packet.get('quic.long.packet_type'):
                    info = f"QUIC packet type {packet['quic.long.packet_type']}"
                elif packet.get('tcp.flags'):
                    info = f"Flags 0x{packet['tcp.flags']}"
                elif packet.get('tls.record.content_type'):
                    info = 'Application Data'
            packet_data = {
                'number': packet.get('frame.number', ''),
                'time': datetime.utcfromtimestamp(packet.get('frame.time_epoch', 0)).isoformat()
                    if packet.get('frame.time_epoch') else datetime.utcnow().isoformat(),
                'relative_time': round(epoch - _first_packet_epoch, 6)
                    if epoch and _first_packet_epoch is not None else 0,
                'src_ip': packet.get('ip.src') or packet.get('ipv6.src', ''),
                'dst_ip': packet.get('ip.dst') or packet.get('ipv6.dst', ''),
                'src_port': packet.get('tcp.srcport') or packet.get('udp.srcport', ''),
                'dst_port': packet.get('tcp.dstport') or packet.get('udp.dstport', ''),
                'protocol': protocol,
                'length': packet.get('frame.len', 0),
                'flags': packet.get('tcp.flags', ''),
                'info': info,
                'ttl': packet.get('ip.ttl', ''),
                'direction': (
                    'IN'
                    if _normalize_ip_address(packet.get('ip.dst') or packet.get('ipv6.dst', ''))
                    in _tshark_capture.local_ips
                    else 'OUT'
                ),
            }
            with packet_batch_lock:
                _live_packets.append(packet_data)
                if len(_live_packets) > 2000:
                    _live_packets = _live_packets[-2000:]
            now = time.monotonic()
            with packet_batch_lock:
                packet_batch.append(packet_data)
                if len(packet_batch) > max_pending_packets:
                    del packet_batch[:-max_pending_packets]
                if now - last_packet_emit[0] < 0.5:
                    return
                packets = packet_batch[-100:]
                packet_batch.clear()
                last_packet_emit[0] = now

            # Batch updates twice per second instead of opening a polling
            # response for every packet.
            socketio.emit('network_update', {
                'stats': {
                    'capture_mode': 'tshark',
                    'packets_captured': _tshark_capture.packets_captured,
                },
                'packets': packets,
            })
        
        _tshark_capture.packet_callback = on_packet

        # Start packet capture automatically on the adapter that owns the
        # backend's local IP. The user should not need to select an interface
        # manually just to see live traffic on the SOC dashboard.
        import psutil
        from models.network_monitor import _get_local_ip
        local_ip = _get_local_ip()
        _tshark_capture.local_ip = local_ip
        _tshark_capture.local_ips = {local_ip}
        interfaces = _tshark_capture.get_interfaces()
        interface_addresses = psutil.net_if_addrs()
        local_addresses = {
            _normalize_ip_address(getattr(address, 'address', ''))
            for addresses in interface_addresses.values()
            for address in addresses
            if getattr(address, 'address', '')
        }
        local_addresses.discard('')
        _tshark_capture.local_ips = local_addresses | {_normalize_ip_address(local_ip)}
        interface = None
        for item in interfaces:
            for name, addresses in interface_addresses.items():
                if name.lower() != item['name'].lower():
                    continue
                ips = {
                    _normalize_ip_address(getattr(address, 'address', ''))
                    for address in addresses
                    if getattr(address, 'address', '')
                }
                if _normalize_ip_address(local_ip) in ips:
                    interface = item['device']
                    break
            if interface:
                break
        if interface and _tshark_capture.start_capture(interface, on_packet):
            print(f"[OK] Wireshark capture started automatically on {interface}")
        else:
            print("[WARN] Wireshark capture could not start automatically; use /api/capture/start")

        print("[OK] Real-time capture initialized")
        return True
        
    except Exception as e:
        print(f"[WARN] Real-time capture init failed: {e}")
        return False


# Call initialization
init_realtime_capture()


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if _tshark_capture is None:
        return jsonify({'interfaces': [], 'error': 'Capture not initialized'}), 500
    
    interfaces = _tshark_capture.get_interfaces()
    return jsonify({'interfaces': interfaces})


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start live packet capture"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if _tshark_capture is None:
        return jsonify({'error': 'Capture not initialized'}), 500
    
    data = request.get_json()
    interface = data.get('interface')
    filter_expr = data.get('filter', '')
    
    if not interface:
        return jsonify({'error': 'Interface required'}), 400
    
    if _tshark_capture.start_capture(interface, _flow_extractor.add_packet, filter_expr):
        socketio.emit('capture_status', {'status': 'started', 'interface': interface})
        return jsonify({'status': 'started', 'interface': interface})
    else:
        return jsonify({'error': 'Failed to start capture'}), 500


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop live packet capture"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if _tshark_capture is None:
        return jsonify({'error': 'Capture not initialized'}), 500
    
    _tshark_capture.stop_capture()
    socketio.emit('capture_status', {'status': 'stopped'})
    return jsonify({'status': 'stopped'})


@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    """Get capture status"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if _tshark_capture is None:
        return jsonify({'status': 'not_initialized'}), 500
    
    status = _tshark_capture.get_status()
    status['active_flows'] = _flow_extractor.get_flow_count() if _flow_extractor else 0
    return jsonify(status)


@app.route('/api/flows', methods=['GET'])
def get_flows():
    """Get live network flows"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    limit = int(request.args.get('limit', 100))
    return jsonify({'flows': _live_flows[-limit:], 'total': len(_live_flows)})


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get live alerts"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    limit = int(request.args.get('limit', 50))
    return jsonify({'alerts': list(reversed(_live_alerts[-limit:])), 'total': len(_live_alerts)})


@app.route('/api/attackers', methods=['GET'])
def get_attackers():
    """Get tracked attackers"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    attackers_list = []
    for ip, data in _attackers.items():
        attackers_list.append({
            'ip': data['ip'],
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'attempts': data['attempts'],
            'packets': data['packets'],
            'flows': data['flows'],
            'attack_types': list(data['attack_types']),
            'risk_score': data['risk_score'],
        })
    
    return jsonify({'attackers': attackers_list, 'total': len(attackers_list)})


@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Get overall system status"""
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    
    status = {
        'capture': _tshark_capture.get_status() if _tshark_capture else {'is_capturing': False},
        'ml_loaded': _ml_predictor.is_loaded if _ml_predictor else False,
        'active_flows': _flow_extractor.get_flow_count() if _flow_extractor else 0,
        'total_alerts': len(_live_alerts),
        'total_attackers': len(_attackers),
        'total_flows': len(_live_flows),
    }
    
    return jsonify(status)


# ═════════════════════════════════════════════════════════
# NETWORK MONITOR (LEGACY - KEPT FOR COMPATIBILITY)
# ═════════════════════════════════════════════════════════

def start_network_monitor():
    try:
        from models.network_monitor import NetworkMonitor, set_monitor
        tshark_active = _tshark_capture is not None and _tshark_capture.is_capturing
        nm = NetworkMonitor(
            socketio,
            blockchain_log,
            send_high_threat_alert,
            capture_packets=not tshark_active,
        )
        set_monitor(nm)
        nm.start()
    except Exception as e:
        print(f"[WARN] Network monitor failed: {e}")

network_thread = threading.Thread(target=start_network_monitor, daemon=True)
network_thread.start()


@app.route('/api/network/connections')
@rate_limit("30 per minute")
def network_connections():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    if m is None:
        return jsonify({'connections': [], 'error': 'Monitor not ready'})
    return jsonify({'connections': m.get_connections()})


@app.route('/api/network/stats')
@rate_limit("30 per minute")
def network_stats():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    stats = m.get_stats() if m is not None else {
        'total_connections': 0, 'suspicious_ips': 0, 'alerts_today': 0,
        'bytes_sent_mb': 0, 'capture_mode': 'unavailable', 'local_ip': '',
        'packets_captured': 0, 'scans_detected': 0, 'brute_force_detected': 0,
    }
    verified_alerts = [
        alert for alert in _live_alerts
        if alert.get('is_verified') is True
        and alert.get('verification') == 'trained_network_ids'
    ]
    today = datetime.utcnow().date().isoformat()
    verified_today = [
        alert for alert in verified_alerts
        if str(alert.get('timestamp', '')).startswith(today)
    ]
    stats.update({
        'alerts_today': len(verified_today),
        'suspicious_ips': len({
            alert.get('attacker_ip') for alert in verified_today
            if alert.get('attacker_ip')
        }),
        'scans_detected': sum(
            1 for alert in verified_today if alert.get('attack_type') == 'PORT_SCAN'
        ),
        'brute_force_detected': sum(
            1 for alert in verified_today if alert.get('attack_type') == 'BRUTE_FORCE'
        ),
    })
    # TShark is the packet-level source of truth. Do not expose the legacy
    # psutil/raw-socket mode while the Wi-Fi capture is still running.
    if _tshark_capture is not None and _tshark_capture.is_capturing:
        stats['capture_mode'] = 'tshark'
        stats['packets_captured'] = _tshark_capture.packets_captured
    return jsonify(stats)


@app.route('/api/network/alerts')
@rate_limit("30 per minute")
def network_alerts():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    if m is None:
        return jsonify({'alerts': []})
    return jsonify({'alerts': m.get_alerts()})


@app.route('/api/network/packets')
@rate_limit("30 per minute")
def network_packets():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    packets = list(_live_packets)
    if packets:
        return jsonify({'packets': list(reversed(packets[-250:])), 'source': 'tshark'})
    if m is None:
        return jsonify({'packets': [], 'error': 'Monitor not ready'})
    return jsonify({'packets': m.get_packets()[:250], 'source': 'network-monitor'})


# ═════════════════════════════════════════════════════════
# UNIFIED SECURITY EVENTS
# ═════════════════════════════════════════════════════════

@app.route('/api/events', methods=['GET'])
def get_events():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_security_events
    limit       = int(request.args.get('limit', 200))
    scenario_id = request.args.get('scenario_id')
    event_type  = request.args.get('event_type')
    severity    = request.args.get('severity')
    events = get_security_events(limit=limit, scenario_id=scenario_id,
                                  event_type=event_type, severity=severity)
    return jsonify({'events': events, 'count': len(events)})


# ═════════════════════════════════════════════════════════
# INCIDENTS
# ═════════════════════════════════════════════════════════

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.incident_manager import get_all_incidents
    limit  = int(request.args.get('limit', 100))
    status = request.args.get('status')
    return jsonify({'incidents': get_all_incidents(limit=limit, status=status)})


@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.incident_manager import get_incident as _get_inc
    inc = _get_inc(incident_id)
    if not inc:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(inc)


@app.route('/api/incidents/<incident_id>/investigate', methods=['GET'])
def investigate_incident(incident_id):
    """AI-assisted incident investigation using actual event data."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.incident_manager import get_incident as _get_inc
    from utils.chatbot import chat as ai_chat

    inc = _get_inc(incident_id)
    if not inc:
        return jsonify({'error': 'Not found'}), 404

    # Build investigation prompt from real incident data
    timeline_entries = inc.get('timeline', [])
    timeline_str = '\n'.join(
        f"  [{e.get('time','?')[:19]}] {e.get('event','?')}"
        for e in (timeline_entries if isinstance(timeline_entries, list) else [])[:10]
    )

    geo = inc.get('geo_info') or {}
    geo_str = f"{geo.get('city','?')}, {geo.get('country','?')}" if isinstance(geo, dict) and geo.get('country') else 'Local/Private'

    prompt = (
        f"Analyze this security incident and provide a concise investigation summary:\n\n"
        f"Incident ID: {inc.get('id')}\n"
        f"Attack Type: {inc.get('attack_type')}\n"
        f"Severity: {inc.get('severity')}\n"
        f"Risk Score: {inc.get('risk_score')}/100\n"
        f"Source IP: {inc.get('source_ip') or 'Unknown'}\n"
        f"Source Location: {geo_str}\n"
        f"Process: {inc.get('process_name') or 'Unknown'} (PID {inc.get('process_pid') or 'Unknown'})\n"
        f"Files Affected: {inc.get('files_affected', 0)}\n"
        f"Honeypot Hit: {inc.get('honeypot_hit')}\n"
        f"ML Prediction: {inc.get('ml_prediction') or 'N/A'} ({inc.get('ml_confidence', 0):.1f}%)\n"
        f"Response: {inc.get('response')}\n\n"
        f"Timeline:\n{timeline_str or 'No timeline data'}\n\n"
        f"Provide: 1) What happened 2) Why classified as {inc.get('attack_type')} "
        f"3) What actions were taken. Use ONLY the data above. "
        f"If information is unavailable, say 'Not available from collected telemetry'."
    )

    try:
        investigation = ai_chat(prompt, context={}, history=[])
    except Exception:
        investigation = (
            f"Incident {inc.get('id')} involves a {inc.get('attack_type')} attack "
            f"with risk score {inc.get('risk_score')}/100. "
            f"Source: {inc.get('source_ip') or 'Unknown'}. "
            f"Response: {inc.get('response') or 'Monitoring'}."
        )

    return jsonify({
        'incident_id':   incident_id,
        'investigation': investigation,
        'incident':      inc,
    })


@app.route('/api/incidents/<incident_id>/evidence', methods=['GET'])
def get_incident_evidence(incident_id):
    """Get or generate forensic evidence bundle for an incident."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.incident_manager import get_incident as _get_inc
    from utils.forensic_evidence import preserve_evidence, get_evidence_bundle
    from utils.db import get_security_events, get_honeypot_triggers

    inc = _get_inc(incident_id)
    if not inc:
        return jsonify({'error': 'Not found'}), 404

    # Return cached bundle if exists
    bundle = get_evidence_bundle(incident_id)
    if bundle:
        return jsonify({'bundle': bundle, 'cached': True})

    # Generate new bundle
    scenario_id = inc.get('scenario_id')
    events    = get_security_events(limit=50, scenario_id=scenario_id) if scenario_id else []
    hp_events = get_honeypot_triggers(limit=20)

    result = preserve_evidence(
        incident=inc,
        events=events,
        honeypot_events=hp_events,
    )

    bundle = get_evidence_bundle(incident_id)
    return jsonify({'bundle': bundle, 'cached': False, 'hash': result.get('evidence_hash')})


@app.route('/api/incidents/<incident_id>/replay', methods=['GET'])
def replay_incident(incident_id):
    """Return the recorded event sequence for incident replay."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.incident_manager import get_incident as _get_inc
    from utils.db import get_security_events

    inc = _get_inc(incident_id)
    if not inc:
        return jsonify({'error': 'Not found'}), 404

    scenario_id = inc.get('scenario_id')
    events = get_security_events(limit=200, scenario_id=scenario_id) if scenario_id else []

    # Return in chronological order
    events_sorted = sorted(events, key=lambda e: e.get('timestamp', ''))

    return jsonify({
        'incident_id': incident_id,
        'incident':    inc,
        'events':      events_sorted,
        'event_count': len(events_sorted),
    })


@app.route('/api/incidents/<incident_id>/attack-graph', methods=['GET'])
def get_attack_graph(incident_id):
    """Build attack graph nodes and edges from incident events."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.incident_manager import get_incident as _get_inc
    from utils.db import get_security_events

    inc = _get_inc(incident_id)
    if not inc:
        return jsonify({'error': 'Not found'}), 404

    scenario_id = inc.get('scenario_id')
    events = get_security_events(limit=100, scenario_id=scenario_id) if scenario_id else []

    nodes = {}
    edges = []

    def _add_node(node_id, label, ntype, severity='LOW'):
        if node_id not in nodes:
            nodes[node_id] = {'id': node_id, 'label': label, 'type': ntype, 'severity': severity}

    def _add_edge(src, dst, label=''):
        edge = {'source': src, 'target': dst, 'label': label}
        if edge not in edges:
            edges.append(edge)

    # Source IP node
    src_ip = inc.get('source_ip')
    if src_ip:
        _add_node(f'ip_{src_ip}', src_ip, 'ip', inc.get('severity', 'LOW'))

    # Process node
    proc = inc.get('process_name')
    if proc:
        _add_node(f'proc_{proc}', proc, 'process', 'HIGH')
        if src_ip:
            _add_edge(f'ip_{src_ip}', f'proc_{proc}', 'spawned')

    for ev in events:
        etype = ev.get('event_type', '')
        sev   = ev.get('severity', 'LOW')

        if 'HONEYPOT' in etype:
            hp_res = (ev.get('honeypot') or {}).get('resource') or 'honeypot'
            _add_node(f'hp_{hp_res}', hp_res, 'honeypot', 'CRITICAL')
            if proc:
                _add_edge(f'proc_{proc}', f'hp_{hp_res}', 'accessed')

        elif 'FILE' in etype:
            fname = (ev.get('file') or {}).get('name', 'file')
            _add_node(f'file_{fname}', fname, 'file', sev)
            if proc:
                _add_edge(f'proc_{proc}', f'file_{fname}', 'created')

        elif 'NETWORK' in etype or 'PORT_SCAN' in etype or 'BRUTE' in etype:
            dst_ip = (ev.get('destination') or {}).get('ip') or 'target'
            _add_node(f'dst_{dst_ip}', dst_ip, 'destination', sev)
            ev_src = (ev.get('source') or {}).get('ip') or src_ip
            if ev_src:
                _add_node(f'ip_{ev_src}', ev_src, 'ip', sev)
                _add_edge(f'ip_{ev_src}', f'dst_{dst_ip}', etype)

    # ML Engine node
    if inc.get('ml_prediction'):
        _add_node('ml_engine', 'ML ENGINE', 'ml', inc.get('severity', 'LOW'))
        if proc:
            _add_edge(f'proc_{proc}', 'ml_engine', 'analysed')
        _add_node('incident', 'INCIDENT', 'incident', inc.get('severity', 'LOW'))
        _add_edge('ml_engine', 'incident', 'detected')
        _add_node('response', f"RESPONSE: {inc.get('response','?')}", 'response', 'LOW')
        _add_edge('incident', 'response', 'triggered')

    return jsonify({
        'nodes': list(nodes.values()),
        'edges': edges,
        'incident_id': incident_id,
    })


# ═════════════════════════════════════════════════════════
# HONEYPOT
# ═════════════════════════════════════════════════════════

@app.route('/api/honeypot/files', methods=['GET'])
def honeypot_files():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.honeypot import get_honeypot_files
    return jsonify({'files': get_honeypot_files()})


@app.route('/api/honeypot/triggers', methods=['GET'])
def honeypot_triggers():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_honeypot_triggers, count_verified_honeypot_triggers_since
    limit = int(request.args.get('limit', 100))
    today_utc = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    triggers = get_honeypot_triggers(limit, verified_only=True)
    return jsonify({
        'triggers': triggers,
        'verified_hits_today': count_verified_honeypot_triggers_since(today_utc),
    })


@app.route('/api/honeypot/status', methods=['GET'])
def honeypot_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.honeypot import get_trigger_count, get_honeypot_files, get_watcher_status
    ws = get_watcher_status()
    return jsonify({
        'active':        ws['active'],
        'watcher':       ws['active'],
        'directory':     ws['directory'],
        'file_count':    ws['file_count'],
        'trigger_count': ws['trigger_count'],
    })


# ═════════════════════════════════════════════════════════
# IP GEOLOCATION
# ═════════════════════════════════════════════════════════

@app.route('/api/geo/<path:ip>', methods=['GET'])
def geolocate_ip(ip):
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.geo_lookup import geolocate, format_geo_display
    geo = geolocate(ip)
    return jsonify({
        'ip':      ip,
        'geo':     geo,
        'display': format_geo_display(geo),
    })


# ═════════════════════════════════════════════════════════
# EVIDENCE & VERIFICATION
# ═════════════════════════════════════════════════════════

@app.route('/api/evidence', methods=['GET'])
def list_evidence():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.forensic_evidence import list_evidence_bundles
    return jsonify({'bundles': list_evidence_bundles()})


@app.route('/api/evidence/verify', methods=['POST'])
def verify_evidence():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.forensic_evidence import verify_evidence as _verify
    data     = request.get_json()
    filepath = data.get('filepath', '')
    expected = data.get('expected_hash', '')
    if not filepath or not expected:
        return jsonify({'error': 'filepath and expected_hash required'}), 400
    return jsonify(_verify(filepath, expected))


# ═════════════════════════════════════════════════════════
# RISK SCORE
# ═════════════════════════════════════════════════════════

@app.route('/api/risk-score', methods=['POST'])
def calculate_risk_score():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.risk_scorer import calculate_risk
    data = request.get_json()
    rs   = calculate_risk(
        ml_prediction=data.get('ml_prediction'),
        ml_confidence=data.get('ml_confidence', 0),
        ml_score=data.get('ml_score', 0),
        file_events=data.get('file_events', 0),
        honeypot_hit=data.get('honeypot_hit', False),
        honeypot_count=data.get('honeypot_count', 0),
        network_alert=data.get('network_alert'),
        network_severity=data.get('network_severity', 'LOW'),
        process_suspicious=data.get('process_suspicious', False),
        process_risk=data.get('process_risk', 'LOW'),
        correlated_signals=data.get('correlated_signals', 0),
    )
    return jsonify(rs.to_dict())


# ═════════════════════════════════════════════════════════
# CYBER LAB (simulation control)
# ═════════════════════════════════════════════════════════

_lab_mode = False


@app.route('/api/lab/mode', methods=['GET', 'POST'])
def lab_mode():
    global _lab_mode
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if request.method == 'POST':
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get('enabled'), bool):
            return jsonify({'error': 'enabled must be a boolean'}), 400
        _lab_mode = data['enabled']
        log_audit(user.get('username'), 'LAB_MODE_CHANGED', f'enabled={_lab_mode}')
        return jsonify({'lab_mode': _lab_mode})
    return jsonify({'lab_mode': _lab_mode})


@app.route('/api/lab/simulate', methods=['POST'])
def lab_simulate():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not _lab_mode:
        return jsonify({
            'error': 'Enable simulation mode before starting a Cyber Range scenario'
        }), 409

    data = request.get_json(silent=True)
    simulation_type = data.get('type') if isinstance(data, dict) else None
    if not isinstance(simulation_type, str):
        return jsonify({'error': 'A simulation type is required'}), 400

    from utils.attack_director import SIMULATION_MAP, get_active_scenario, run_simulation
    if simulation_type not in SIMULATION_MAP:
        return jsonify({
            'error': 'Unknown simulation type',
            'available_types': sorted(SIMULATION_MAP),
        }), 400
    active_scenario = get_active_scenario()
    if active_scenario:
        return jsonify({
            'error': 'A simulation is already running',
            'active_scenario': active_scenario,
        }), 409

    try:
        scenario_id = run_simulation(simulation_type)
    except RuntimeError as error:
        return jsonify({'error': str(error)}), 409
    if not scenario_id:
        return jsonify({'error': 'Simulation could not be started'}), 500

    log_audit(
        user.get('username'),
        'SIMULATION_STARTED',
        f'type={simulation_type}; scenario_id={scenario_id}',
    )
    return jsonify({
        'scenario_id': scenario_id,
        'type': simulation_type,
        'simulated': True,
        'message': 'Synthetic lab events started; this scenario does not generate captured network packets.',
    }), 202


@app.route('/api/lab/status', methods=['GET'])
def lab_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.attack_director import get_active_scenario, get_scenario_status
    from utils.honeypot import get_trigger_count
    from models.network_scorer import get_status as get_network_model_status

    network_model_status = get_network_model_status()

    return jsonify({
        'lab_mode':         _lab_mode,
        'active_scenario':  get_active_scenario(),
        'scenarios':        get_scenario_status(),
        'network_model_online': network_model_status.get('network_ids_loaded', False),
        'packet_capture_active': bool(
            _tshark_capture and _tshark_capture.is_capturing
        ),
        'blockchain_mode':  bc_logger.mode if bc_logger else 'unavailable',
        'honeypot_active':  True,
        'honeypot_triggers': get_trigger_count(),
    })


@app.route('/api/lab/stop', methods=['POST'])
def lab_stop():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.attack_director import get_active_scenario, request_stop_scenario
    active = get_active_scenario()
    if active:
        if not request_stop_scenario(active):
            return jsonify({'message': 'No active simulation'}), 409
        log_audit(user.get('username'), 'SIMULATION_STOPPED', active)
        return jsonify({'message': f'Stopping simulation {active}'}), 202
    return jsonify({'message': 'No active simulation'})


@app.route('/api/lab/reset', methods=['POST'])
def lab_reset():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_sim_log
    # Clear simulation log entries and watched dir
    import sqlite3 as _sq
    try:
        conn = _sq.connect('cyberdefense.db')
        conn.execute('DELETE FROM simulation_log')
        conn.execute('DELETE FROM security_events')
        conn.execute('DELETE FROM honeypot_triggers')
        conn.commit()
        conn.close()
    except Exception:
        pass

    # Clear watched folder
    watched = os.path.join(os.path.dirname(__file__), 'watched')
    cleared = 0
    if os.path.exists(watched):
        for f in os.listdir(watched):
            try:
                os.remove(os.path.join(watched, f))
                cleared += 1
            except Exception:
                pass

    log_audit(user.get('username'), 'LAB_RESET', f'cleared {cleared} files')
    return jsonify({'message': f'Lab reset. Removed {cleared} files from watched/'})


@app.route('/api/lab/logs/<scenario_id>', methods=['GET'])
def lab_logs(scenario_id):
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_sim_log
    return jsonify({'logs': get_sim_log(scenario_id)})


@app.route('/api/lab/scenarios', methods=['GET'])
def lab_scenarios():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.attack_director import get_scenario_status
    return jsonify({'scenarios': get_scenario_status()})


# ═════════════════════════════════════════════════════════
# THREAT INTELLIGENCE (AbuseIPDB + Shodan + VirusTotal)
# ═════════════════════════════════════════════════════════

@app.route('/api/intel/ip/<path:ip>', methods=['GET'])
def intel_ip(ip):
    """Full IP enrichment — AbuseIPDB + Shodan."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.threat_intel import enrich_ip
    result = enrich_ip(ip, background=False)
    return jsonify(result)


@app.route('/api/intel/ip/<path:ip>/abuse', methods=['GET'])
def intel_ip_abuse(ip):
    """AbuseIPDB check only."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.threat_intel import check_abuseipdb
    return jsonify(check_abuseipdb(ip))


@app.route('/api/intel/ip/<path:ip>/shodan', methods=['GET'])
def intel_ip_shodan(ip):
    """Shodan host lookup only."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.threat_intel import check_shodan
    return jsonify(check_shodan(ip))


@app.route('/api/intel/hash/<file_hash>', methods=['GET'])
def intel_hash(file_hash):
    """VirusTotal file hash check."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.threat_intel import check_virustotal_hash
    return jsonify(check_virustotal_hash(file_hash))


@app.route('/api/intel/status', methods=['GET'])
def intel_status():
    """Which threat intel APIs are configured."""
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.threat_intel import get_enrichment_status
    return jsonify(get_enrichment_status())


# ═════════════════════════════════════════════════════════
# NETWORK AUDIT LOG (existing api.js references this)
# ═════════════════════════════════════════════════════════

@app.route('/api/network/audit-log', methods=['GET'])
def network_audit_log():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_network_audit_logs
    limit = int(request.args.get('limit', 500))
    return jsonify(get_network_audit_logs(limit))


def _build_live_incident_from_alert(alert: dict, scenario_id: str = None):
    """Build and emit a live_incident payload from a network alert dict."""
    import socket as _socket
    try:
        from utils.geo_lookup import geolocate, format_geo_display, is_private_ip
        from utils.risk_scorer import calculate_risk
        from utils.incident_manager import create_incident

        ip        = alert.get('ip', '')
        alert_type = alert.get('type', 'UNKNOWN')
        severity  = alert.get('severity', 'HIGH')
        desc      = alert.get('description', '')

        geo_raw     = geolocate(ip) if ip else {}
        geo_display = format_geo_display(geo_raw) if geo_raw else {}

        # ── Threat Intelligence enrichment ──────────────
        threat_intel = {}
        try:
            from utils.threat_intel import enrich_ip, get_enrichment_status
            if get_enrichment_status().get('any_active') and ip and not is_private_ip(ip):
                threat_intel = enrich_ip(ip, background=False)
                abuse_score = threat_intel.get('abuseipdb', {}).get('abuse_score', 0)
                shodan_ports = threat_intel.get('shodan', {}).get('port_count', 0)
                print(f"[INTEL] {ip} -> Abuse={abuse_score}% Shodan={shodan_ports} ports CVEs={threat_intel.get('shodan',{}).get('cve_count',0)}")
        except Exception as te:
            print(f"[INFO] Threat intel skipped: {te}")

        local_ip = '127.0.0.1'
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        rs = calculate_risk(
            network_alert=alert_type,
            network_severity=severity,
            correlated_signals=3 if scenario_id else 2,
        )

        mitre_map = {
            'PORT_SCAN':   ('T1046', 'Network Service Discovery'),
            'BRUTE_FORCE': ('T1110', 'Brute Force'),
            'C2_BEACON':   ('T1071', 'Application Layer Protocol'),
            'DATA_EXFIL':  ('T1041', 'Exfiltration Over C2 Channel'),
        }
        mitre_id, mitre_name = mitre_map.get(alert_type, ('T1046', 'Network Activity'))

        now = datetime.utcnow().isoformat()
        dest_port = alert.get('target_port') or 0
        protocol  = {'PORT_SCAN': 'TCP', 'BRUTE_FORCE': 'TCP', 'C2_BEACON': 'HTTPS', 'DATA_EXFIL': 'TCP'}.get(alert_type, 'TCP')

        incident = create_incident(
            attack_type=alert_type,
            title=f'{alert_type.replace("_"," ")} from {ip}',
            severity=severity,
            scenario_id=scenario_id,
            source_ip=ip,
            dest_ip=local_ip,
            dest_port=dest_port,
            protocol=protocol,
            geo_info=geo_display,
            initial_events=[{'time': now, 'event': f'{alert_type} detected', 'description': desc, 'severity': severity}],
        )

        payload = {
            'incident_id':   incident.get('id'),
            'attack_type':   alert_type,
            'title':         incident.get('title'),
            'severity':      severity,
            'risk_score':    rs.final_score,
            'risk_level':    rs.risk_level,
            'description':   desc,
            'timestamp':     now,
            'scenario_id':   scenario_id,
            'attacker': {
                'ip':       ip,
                'port':     alert.get('source_port'),
                'protocol': protocol,
                'mac':      'Not observable remotely' if not is_private_ip(ip) else 'Unknown (local)',
                'geo':      geo_display,
            },
            'threat_intel':  threat_intel,
            'target':        {'ip': local_ip, 'port': dest_port},
            'network': {
                'ports_hit':        alert.get('ports_hit', []),
                'connection_count': alert.get('connection_count', 0),
                'bytes_sent':       alert.get('bytes_sent', 0),
                'target_port':      dest_port,
                'protocol':         protocol,
            },
            'mitre':         {'id': mitre_id, 'name': mitre_name, 'url': f'https://attack.mitre.org/techniques/{mitre_id}/'},
            'risk_factors':  rs.to_dict().get('factors', []),
            'status': {
                'detected':   True,
                'honeypot':   False,
                'ml':         False,
                'quarantine': False,
                'evidence':   False,
                'blockchain': False,
            },
        }
        socketio.emit('live_incident', payload)
        print(f"🚨 live_incident emitted: {alert_type} from {ip} | risk={rs.final_score}/100")
    except Exception as e:
        print(f"⚠️  _build_live_incident_from_alert: {e}")


def _build_live_incident_from_event(event: dict):
    """Build and emit a live_incident payload from a unified security event."""
    import socket as _socket
    try:
        from utils.geo_lookup import geolocate, format_geo_display, is_private_ip
        from utils.risk_scorer import calculate_risk
        from utils.incident_manager import create_incident

        src    = event.get('source') or {}
        proc   = event.get('process') or {}
        atk    = event.get('attack') or {}
        hp     = event.get('honeypot') or {}
        ml     = event.get('ml') or {}
        fobj   = event.get('file') or {}

        ip         = src.get('ip', '')
        severity   = event.get('severity', 'HIGH')
        attack_type = atk.get('type') or event.get('event_type', 'UNKNOWN')
        scenario_id = event.get('scenario_id')
        hp_hit     = bool(hp.get('triggered'))

        geo_raw     = geolocate(ip) if ip else {}
        geo_display = format_geo_display(geo_raw) if geo_raw else {}

        local_ip = '127.0.0.1'
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        rs = calculate_risk(
            ml_prediction    = ml.get('prediction'),
            ml_confidence    = ml.get('confidence', 0),
            honeypot_hit     = hp_hit,
            honeypot_count   = 1 if hp_hit else 0,
            network_alert    = attack_type if 'NETWORK' in (event.get('event_type','').upper()) else None,
            network_severity = severity,
            process_suspicious = bool(proc.get('name')),
            process_risk     = severity,
            correlated_signals = 3 if scenario_id else 1,
        )

        now = datetime.utcnow().isoformat()

        incident = create_incident(
            attack_type=attack_type,
            title=event.get('description') or f'{attack_type} detected',
            severity=severity,
            scenario_id=scenario_id,
            source_ip=ip,
            source_port=src.get('port'),
            dest_ip=local_ip,
            protocol=src.get('protocol'),
            process_name=proc.get('name'),
            process_pid=proc.get('pid'),
            file_name=fobj.get('name'),
            honeypot_hit=hp_hit,
            honeypot_resource=hp.get('resource'),
            ml_prediction=ml.get('prediction'),
            ml_confidence=ml.get('confidence', 0),
            geo_info=geo_display,
            initial_events=[{'time': now, 'event': event.get('event_type',''), 'description': event.get('description',''), 'severity': severity}],
        )

        payload = {
            'incident_id':   incident.get('id'),
            'attack_type':   attack_type,
            'title':         incident.get('title'),
            'severity':      severity,
            'risk_score':    rs.final_score,
            'risk_level':    rs.risk_level,
            'description':   event.get('description', ''),
            'timestamp':     now,
            'scenario_id':   scenario_id,
            'attacker': {
                'ip':       ip,
                'port':     src.get('port'),
                'protocol': src.get('protocol'),
                'mac':      'Not observable remotely' if ip and not is_private_ip(ip) else ('Unknown (local)' if ip else 'Unknown'),
                'geo':      geo_display,
            },
            'target':        {'ip': local_ip, 'port': (event.get('destination') or {}).get('port')},
            'process': {
                'name':   proc.get('name'),
                'pid':    proc.get('pid'),
                'parent': proc.get('parent'),
                'path':   proc.get('path'),
            },
            'file': {
                'name':   fobj.get('name'),
                'sha256': fobj.get('sha256'),
            },
            'honeypot': {
                'triggered': hp_hit,
                'resource':  hp.get('resource'),
            },
            'risk_factors':  rs.to_dict().get('factors', []),
            'status': {
                'detected':   True,
                'honeypot':   hp_hit,
                'ml':         bool(ml.get('prediction')),
                'quarantine': False,
                'evidence':   False,
                'blockchain': False,
            },
        }
        socketio.emit('live_incident', payload)
    except Exception as e:
        print(f"⚠️  _build_live_incident_from_event: {e}")


# ═════════════════════════════════════════════════════════
# STARTUP: Initialize new modules
# ═════════════════════════════════════════════════════════

def _init_new_modules():
    """Initialize all new modules after app startup."""
    try:
        # Ensure new DB tables exist
        from utils.db import init_db as _init_db
        _init_db()
    except Exception:
        pass

    try:
        # Honeypot setup + active filesystem watcher
        from utils.honeypot import setup_honeypot, register_callback as hp_cb, load_persisted_triggers, start_honeypot_watcher
        setup_honeypot()
        load_persisted_triggers()
        start_honeypot_watcher()   # ← ACTIVE watcher — detects real file access

        def _on_hp_trigger(entry):
            socketio.emit('honeypot_triggered', entry)
            # Save to DB
            try:
                from utils.db import save_honeypot_trigger
                save_honeypot_trigger(entry)
            except Exception:
                pass
        hp_cb(_on_hp_trigger)
    except Exception as e:
        print(f"⚠️  Honeypot init failed: {e}")

    try:
        # Incident manager
        from utils.incident_manager import init_incident_manager
        init_incident_manager(socketio, blockchain_log)
    except Exception as e:
        print(f"⚠️  Incident manager init failed: {e}")

    try:
        # Attack director — register event callback
        from utils.attack_director import register_output_callback, register_event_callback
        from utils.db import save_security_event, save_sim_log

        def _on_sim_output(entry):
            socketio.emit('sim_log', entry)
            if entry.get('scenario_id'):
                try:
                    save_sim_log(
                        entry['scenario_id'],
                        entry.get('message', ''),
                        sim_type=entry.get('scenario_id', '').split('_')[0] if '_' in entry.get('scenario_id', '') else '',
                    )
                except Exception:
                    pass

        def _on_sim_event(event):
            # Handle network alerts (already have type, ip, etc.)
            if '_network_alert' in event:
                alert = event['_network_alert']
                socketio.emit('network_alert', alert)
                # Also build a live_incident for sim network alerts
                try:
                    _build_live_incident_from_alert(alert, event.get('scenario_id'))
                except Exception:
                    pass
                try:
                    from utils.db import log_network_audit
                    log_network_audit(
                        event_type=alert.get('type', 'SIM'),
                        ip=alert.get('ip', ''),
                        severity=alert.get('severity', 'HIGH'),
                        description=alert.get('description', ''),
                        details=json.dumps({'scenario_id': event.get('scenario_id')}),
                    )
                except Exception:
                    pass
                return

            # Save unified event
            try:
                save_security_event(event)
            except Exception:
                pass

            # Emit to SOC
            socketio.emit('security_event', event)
            socketio.emit('soc_update', {
                'type':        'security_event',
                'event_type':  event.get('event_type', ''),
                'severity':    event.get('severity', 'LOW'),
                'description': event.get('description', ''),
                'timestamp':   event.get('timestamp', ''),
                'scenario_id': event.get('scenario_id', ''),
            })

            # Build and emit live_incident for CRITICAL/HIGH simulation events
            if event.get('severity') in ('CRITICAL', 'HIGH'):
                try:
                    _build_live_incident_from_event(event)
                except Exception:
                    pass
                socketio.emit('high_threat_alert', {
                    'prediction':   event.get('attack', {}).get('type', event.get('event_type')),
                    'threat_score': 85 if event.get('severity') == 'CRITICAL' else 75,
                    'risk_level':   event.get('severity', 'HIGH'),
                    'timestamp':    event.get('timestamp', ''),
                    'scenario_id':  event.get('scenario_id', ''),
                    'source_ip':    (event.get('source') or {}).get('ip', ''),
                    'process_name': (event.get('process') or {}).get('name', ''),
                    'event_type':   event.get('event_type', ''),
                })

            # Feed to threat correlator
            try:
                from utils.threat_correlator import ingest
                ingest(event)
            except Exception:
                pass

        register_output_callback(_on_sim_output)
        register_event_callback(_on_sim_event)
        print("✅ Attack director ready")

    except Exception as e:
        print(f"⚠️  Attack director init failed: {e}")

    print("✅ CyberDefense-AI SOC Platform ready")
    print(f"   ML       : ONLINE")
    print(f"   Honeypot : ACTIVE")
    print(f"   Lab Mode : READY")
    print(f"   CLI      : python cyberdefense_cli.py")


# Run after a short delay to let Flask/SocketIO boot
threading.Timer(2.0, _init_new_modules).start()


# ═════════════════════════════════════════════════════════
# RUN
# ═════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("🛡️  CyberDefense Backend starting on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
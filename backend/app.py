import os
import json
import hashlib
import sqlite3
import threading
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=False)

init_db()

# ── Rate Limiting ─────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])
    LIMITER_AVAILABLE = True
    print("✅ Rate limiter ready")
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
    print(f"⛓  Blockchain mode : {bc_logger.mode}")
    if bc_logger.mode == 'core_testnet2':
        print(f"✅ Blockchain ready : {os.getenv('CONTRACT_ADDRESS')}")
    else:
        print(f"ℹ️  Blockchain      : local simulation")
except Exception as e:
    print(f"⚠️  Blockchain init failed: {e}")
    bc_logger              = None
    blockchain_log         = None
    blockchain_verify_hash = None
    blockchain_get_logs    = None

# ── Email ─────────────────────────────────────────────────
try:
    from utils.email_alerts import send_high_threat_alert, send_system_startup_email
    EMAIL_AVAILABLE = True
    print("✅ Email alerts ready")
except Exception as e:
    EMAIL_AVAILABLE           = False
    send_high_threat_alert    = None
    send_system_startup_email = None
    print(f"⚠️  Email init failed: {e}")

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
            print(f"⚠️  Blockchain log failed: {e}")

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
                    print(f"⚠️  AI summary failed: {ex}")
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
    if not EMAIL_AVAILABLE or not send_high_threat_alert:
        return jsonify({'error': 'Email not configured'}), 503
    test_data = {
        'threat_score':  99.0,
        'prediction':    'Ransomware',
        'risk_level':    'HIGH',
        'timestamp':     datetime.utcnow().isoformat(),
        'file_name':     'test_malware.dll',
        'hash':          'abc123def456test',
        'top_features':  ['BitcoinAddresses=1', 'DllCharacteristics=0', 'NumberOfSections=6'],
        'ml_confidence': 99.0,
        'dl_confidence': 98.0,
        'blockchain':    {'mode': 'test', 'block': 999999, 'explorer': None}
    }
    threading.Thread(
        target=send_high_threat_alert,
        args=(test_data,),
        daemon=True
    ).start()
    return jsonify({'status': 'Test email sent!'})


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
    print(f"🗑️  Quarantine cleared: {cleared} files")
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
        print("🗑️  Threat database cleared")
        return jsonify({'status': 'Threat database cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        print(f"⚙️  Threat threshold updated: {threshold}")
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
# TEST ALERT
# ═════════════════════════════════════════════════════════

@app.route('/api/test-alert', methods=['POST'])
def test_alert():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    socketio.emit('high_threat_alert', {
        'prediction':   'Ransomware',
        'threat_score': 95.0,
        'risk_level':   'HIGH',
        'timestamp':    datetime.utcnow().isoformat()
    })
    print("🚨 Test alert emitted!")
    return jsonify({'status': 'alert sent'})


# ═════════════════════════════════════════════════════════
# WEBSOCKET
# ═════════════════════════════════════════════════════════

@socketio.on('connect')
def on_connect():
    emit('connected', {'message': '🛡️ CyberDefense SOC connected'})
    print("✅ Client connected via WebSocket")


@socketio.on('disconnect')
def on_disconnect():
    print("⚠️  Client disconnected")


# ═════════════════════════════════════════════════════════
# FILE MONITOR
# ═════════════════════════════════════════════════════════

def start_file_monitor():
    try:
        import time
        from watchdog.observers import Observer
        from models.file_monitor import ThreatHandler, WATCHED_DIR, reset_token
        os.makedirs(WATCHED_DIR, exist_ok=True)
        print(f"👁️  File monitor waiting for server...")
        time.sleep(3)
        reset_token()
        handler  = ThreatHandler()
        observer = Observer()
        observer.schedule(handler, WATCHED_DIR, recursive=False)
        observer.start()
        print(f"👁️  File monitor started: {WATCHED_DIR}")
        # Scan files that were already in watched/ before the monitor started
        from models.file_monitor import scan_existing_files
        scan_existing_files()
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"⚠️  File monitor failed: {e}")

monitor_thread = threading.Thread(target=start_file_monitor, daemon=True)
monitor_thread.start()


# ═════════════════════════════════════════════════════════
# NETWORK MONITOR
# ═════════════════════════════════════════════════════════

def start_network_monitor():
    try:
        from models.network_monitor import NetworkMonitor, set_monitor
        nm = NetworkMonitor(socketio, blockchain_log, send_high_threat_alert)
        set_monitor(nm)
        nm.start()
    except Exception as e:
        print(f"⚠️  Network monitor failed: {e}")

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
    if m is None:
        return jsonify({'total_connections': 0, 'suspicious_ips': 0,
                        'alerts_today': 0, 'bytes_sent_mb': 0,
                        'capture_mode': 'unavailable', 'local_ip': '',
                        'packets_captured': 0, 'scans_detected': 0,
                        'brute_force_detected': 0})
    return jsonify(m.get_stats())


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
    if m is None:
        return jsonify({'packets': [], 'error': 'Monitor not ready'})
    return jsonify({'packets': m.get_packets()})


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
    from utils.db import get_honeypot_triggers
    limit = int(request.args.get('limit', 100))
    return jsonify({'triggers': get_honeypot_triggers(limit)})


@app.route('/api/honeypot/status', methods=['GET'])
def honeypot_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.honeypot import get_trigger_count, get_honeypot_files
    return jsonify({
        'active':        True,
        'file_count':    len(get_honeypot_files()),
        'trigger_count': get_trigger_count(),
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
        data = request.get_json()
        _lab_mode = bool(data.get('enabled', False))
        log_audit(user.get('username'), 'LAB_MODE_CHANGED', f'enabled={_lab_mode}')
        return jsonify({'lab_mode': _lab_mode})
    return jsonify({'lab_mode': _lab_mode})


@app.route('/api/lab/simulate', methods=['POST'])
def lab_simulate():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.attack_director import run_simulation, get_active_scenario, get_scenario_status
    data     = request.get_json()
    sim_type = data.get('type', '').strip().lower()

    if not sim_type:
        return jsonify({'error': 'type is required'}), 400

    # Check both the live lock and the scenario status (covers fast-completing sims)
    active = get_active_scenario()
    if not active:
        # Also check if any scenario is still marked RUNNING
        statuses = get_scenario_status()
        active = next((sid for sid, s in statuses.items()
                       if s.get('status') == 'RUNNING'), None)

    if active:
        return jsonify({'error': f'Simulation already running: {active}'}), 409

    scenario_id = run_simulation(sim_type)
    if not scenario_id:
        return jsonify({'error': f'Unknown simulation type: {sim_type}'}), 400

    log_audit(user.get('username'), 'SIMULATION_STARTED', f'type={sim_type} scenario={scenario_id}')
    return jsonify({'scenario_id': scenario_id, 'type': sim_type, 'status': 'STARTED'})


@app.route('/api/lab/status', methods=['GET'])
def lab_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.attack_director import get_active_scenario, get_scenario_status
    from utils.honeypot import get_trigger_count

    return jsonify({
        'lab_mode':         _lab_mode,
        'active_scenario':  get_active_scenario(),
        'scenarios':        get_scenario_status(),
        'ml_online':        True,
        'blockchain_mode':  bc_logger.mode if bc_logger else 'unavailable',
        'honeypot_active':  True,
        'honeypot_triggers': get_trigger_count(),
    })


@app.route('/api/lab/stop', methods=['POST'])
def lab_stop():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.attack_director import _end_scenario, get_active_scenario
    active = get_active_scenario()
    if active:
        _end_scenario(active, status='STOPPED')
        log_audit(user.get('username'), 'SIMULATION_STOPPED', active)
        return jsonify({'message': f'Simulation {active} stopped'})
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
                print(f"🔍 Intel: {ip} → Abuse={abuse_score}% Shodan={shodan_ports} ports CVEs={threat_intel.get('shodan',{}).get('cve_count',0)}")
        except Exception as te:
            print(f"ℹ️  Threat intel skipped: {te}")

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
            ml_prediction    = ml.get('prediction') or (attack_type if 'RANSOM' in attack_type.upper() else None),
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
        # Honeypot setup
        from utils.honeypot import setup_honeypot, register_callback as hp_cb, load_persisted_triggers
        setup_honeypot()
        load_persisted_triggers()

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
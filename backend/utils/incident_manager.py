"""
Incident Manager for CyberDefense-AI
Manages the full incident lifecycle:
  create → enrich → escalate → quarantine → evidence → blockchain → close
Stores incidents in SQLite and emits WebSocket events.
"""
import json
import uuid
import hashlib
import threading
import sqlite3
import os
from datetime import datetime
from typing import Optional, List

from utils.risk_scorer import calculate_risk, RiskScore

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cyberdefense.db')

_lock = threading.Lock()
_socketio = None
_blockchain_fn = None


def init_incident_manager(socketio, blockchain_fn=None):
    global _socketio, _blockchain_fn
    _socketio = socketio
    _blockchain_fn = blockchain_fn
    _ensure_table()
    print("📋 Incident manager initialized")


def _ensure_table():
    """Create incidents table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id              TEXT PRIMARY KEY,
            scenario_id     TEXT,
            title           TEXT,
            status          TEXT DEFAULT 'ACTIVE',
            severity        TEXT DEFAULT 'LOW',
            risk_score      REAL DEFAULT 0,
            risk_level      TEXT DEFAULT 'LOW',
            risk_factors    TEXT,
            attack_type     TEXT,
            source_ip       TEXT,
            source_port     INTEGER,
            dest_ip         TEXT,
            dest_port       INTEGER,
            protocol        TEXT,
            source_mac      TEXT,
            process_name    TEXT,
            process_pid     INTEGER,
            process_path    TEXT,
            file_name       TEXT,
            file_sha256     TEXT,
            files_affected  INTEGER DEFAULT 0,
            honeypot_hit    INTEGER DEFAULT 0,
            honeypot_resource TEXT,
            ml_prediction   TEXT,
            ml_confidence   REAL DEFAULT 0,
            response        TEXT,
            evidence_hash   TEXT,
            blockchain_tx   TEXT,
            geo_info        TEXT,
            timeline        TEXT,
            events          TEXT,
            created_at      TEXT,
            updated_at      TEXT,
            closed_at       TEXT
        )
    ''')
    conn.commit()
    conn.close()


def create_incident(
    attack_type:       str,
    title:             str          = None,
    scenario_id:       str          = None,
    severity:          str          = 'LOW',
    source_ip:         str          = None,
    source_port:       int          = None,
    dest_ip:           str          = None,
    dest_port:         int          = None,
    protocol:          str          = None,
    source_mac:        str          = None,
    process_name:      str          = None,
    process_pid:       int          = None,
    process_path:      str          = None,
    file_name:         str          = None,
    file_sha256:       str          = None,
    files_affected:    int          = 0,
    honeypot_hit:      bool         = False,
    honeypot_resource: str          = None,
    ml_prediction:     str          = None,
    ml_confidence:     float        = 0.0,
    initial_events:    list         = None,
    geo_info:          dict         = None,
) -> dict:
    """Create a new incident record."""
    now  = datetime.utcnow().isoformat()
    inc_id = str(uuid.uuid4())[:12]

    # Calculate initial risk score
    rs = calculate_risk(
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        file_events=files_affected,
        honeypot_hit=honeypot_hit,
        honeypot_count=1 if honeypot_hit else 0,
        process_suspicious=bool(process_name),
    )

    # Build initial timeline entry
    timeline = [{
        'time':        now,
        'event':       f'Incident created: {attack_type}',
        'severity':    severity,
        'description': title or attack_type,
    }]

    incident = {
        'id':               inc_id,
        'scenario_id':      scenario_id,
        'title':            title or f'{attack_type} Detected',
        'status':           'ACTIVE',
        'severity':         severity,
        'risk_score':       rs.final_score,
        'risk_level':       rs.risk_level,
        'risk_factors':     json.dumps(rs.to_dict()),
        'attack_type':      attack_type,
        'source_ip':        source_ip,
        'source_port':      source_port,
        'dest_ip':          dest_ip,
        'dest_port':        dest_port,
        'protocol':         protocol,
        'source_mac':       source_mac,
        'process_name':     process_name,
        'process_pid':      process_pid,
        'process_path':     process_path,
        'file_name':        file_name,
        'file_sha256':      file_sha256,
        'files_affected':   files_affected,
        'honeypot_hit':     1 if honeypot_hit else 0,
        'honeypot_resource': honeypot_resource,
        'ml_prediction':    ml_prediction,
        'ml_confidence':    ml_confidence,
        'response':         'MONITORING',
        'evidence_hash':    None,
        'blockchain_tx':    None,
        'geo_info':         json.dumps(geo_info) if geo_info else None,
        'timeline':         json.dumps(timeline),
        'events':           json.dumps(initial_events or []),
        'created_at':       now,
        'updated_at':       now,
        'closed_at':        None,
    }

    _save_incident(incident)

    # Emit live update
    _emit('incident_created', _to_response(incident))

    return _to_response(incident)


def update_incident(
    incident_id:    str,
    **kwargs
) -> Optional[dict]:
    """Update incident fields and recalculate risk score if needed."""
    incident = _load_incident(incident_id)
    if not incident:
        return None

    now = datetime.utcnow().isoformat()

    # Apply updates
    for k, v in kwargs.items():
        if k in incident:
            if k in ('geo_info', 'risk_factors') and isinstance(v, dict):
                incident[k] = json.dumps(v)
            elif k in ('timeline', 'events') and isinstance(v, list):
                incident[k] = json.dumps(v)
            else:
                incident[k] = v

    incident['updated_at'] = now

    # Add timeline entry if provided
    if 'timeline_entry' in kwargs:
        entry = kwargs['timeline_entry']
        try:
            tl = json.loads(incident.get('timeline') or '[]')
        except Exception:
            tl = []
        tl.append({'time': now, **entry})
        incident['timeline'] = json.dumps(tl)

    _save_incident(incident)
    result = _to_response(incident)
    _emit('incident_updated', result)
    return result


def add_timeline_entry(incident_id: str, event: str, description: str = '', severity: str = 'INFO'):
    """Append an entry to the incident timeline."""
    incident = _load_incident(incident_id)
    if not incident:
        return
    now = datetime.utcnow().isoformat()
    try:
        tl = json.loads(incident.get('timeline') or '[]')
    except Exception:
        tl = []
    tl.append({'time': now, 'event': event, 'description': description, 'severity': severity})
    incident['timeline']   = json.dumps(tl)
    incident['updated_at'] = now
    _save_incident(incident)


def finalize_incident(
    incident_id:  str,
    response:     str    = 'QUARANTINED',
    evidence_hash: str   = None,
    blockchain_tx: str   = None,
) -> Optional[dict]:
    """Close an incident with response actions recorded."""
    incident = _load_incident(incident_id)
    if not incident:
        return None

    now = datetime.utcnow().isoformat()
    incident['status']       = 'CLOSED'
    incident['response']     = response
    incident['evidence_hash'] = evidence_hash
    incident['blockchain_tx'] = blockchain_tx
    incident['closed_at']    = now
    incident['updated_at']   = now

    # Add final timeline entry
    try:
        tl = json.loads(incident.get('timeline') or '[]')
    except Exception:
        tl = []
    tl.append({'time': now, 'event': f'Incident closed: {response}', 'severity': 'INFO'})
    incident['timeline'] = json.dumps(tl)

    # Log to blockchain if function available
    if _blockchain_fn and evidence_hash:
        try:
            bc = _blockchain_fn({
                'prediction':   incident.get('attack_type', 'Unknown'),
                'threat_score': int(incident.get('risk_score', 0)),
                'hash':         evidence_hash,
                'timestamp':    now,
            })
            incident['blockchain_tx'] = bc.get('tx_hash', '')
        except Exception as e:
            print(f"⚠️  Incident blockchain log failed: {e}")

    _save_incident(incident)
    result = _to_response(incident)
    _emit('incident_closed', result)
    return result


def get_incident(incident_id: str) -> Optional[dict]:
    inc = _load_incident(incident_id)
    return _to_response(inc) if inc else None


def get_all_incidents(limit: int = 100, status: str = None) -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    if status:
        c.execute('SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?',
                  (status, limit))
    else:
        c.execute('SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    cols = [d[0] for d in c.description]
    conn.close()
    return [_to_response(dict(zip(cols, r))) for r in rows]


def _save_incident(incident: dict):
    cols   = list(incident.keys())
    vals   = [incident[c] for c in cols]
    ph     = ', '.join(['?'] * len(cols))
    update = ', '.join(f'{c}=excluded.{c}' for c in cols if c != 'id')
    sql    = f'INSERT INTO incidents ({", ".join(cols)}) VALUES ({ph}) ON CONFLICT(id) DO UPDATE SET {update}'
    conn   = sqlite3.connect(DB_PATH)
    conn.execute(sql, vals)
    conn.commit()
    conn.close()


def _load_incident(incident_id: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    row  = c.fetchone()
    cols = [d[0] for d in c.description]
    conn.close()
    return dict(zip(cols, row)) if row else None


def _to_response(incident: dict) -> dict:
    """Deserialize JSON fields and prepare for API response."""
    if not incident:
        return {}
    result = dict(incident)
    for field in ('risk_factors', 'geo_info', 'timeline', 'events'):
        val = result.get(field)
        if isinstance(val, str):
            try:
                result[field] = json.loads(val)
            except Exception:
                result[field] = {} if field in ('risk_factors', 'geo_info') else []
    result['honeypot_hit'] = bool(result.get('honeypot_hit', 0))
    return result


def _emit(event: str, data: dict):
    """Emit a WebSocket event if socketio is available."""
    if _socketio:
        try:
            _socketio.emit(event, data)
        except Exception as e:
            print(f"⚠️  Incident emit {event} failed: {e}")

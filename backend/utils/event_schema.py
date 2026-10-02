"""
Unified Event Schema for CyberDefense-AI
Every security event from any source uses this common structure.
Adapts cleanly to the existing Flask/SocketIO backend.
"""
import uuid
import hashlib
import json
from datetime import datetime


# ── Risk level bands ──────────────────────────────────────
def score_to_risk(score: float) -> str:
    if score >= 76:   return 'CRITICAL'
    if score >= 51:   return 'HIGH'
    if score >= 26:   return 'MODERATE'
    return 'LOW'


def score_to_severity(score: float) -> str:
    if score >= 76:   return 'CRITICAL'
    if score >= 51:   return 'HIGH'
    if score >= 26:   return 'MEDIUM'
    return 'LOW'


def create_event(
    event_type: str,
    severity: str = 'LOW',
    source_ip: str = None,
    source_port: int = None,
    source_mac: str = None,
    source_hostname: str = None,
    source_interface: str = None,
    source_protocol: str = None,
    dest_ip: str = None,
    dest_port: int = None,
    dest_hostname: str = None,
    process_name: str = None,
    process_pid: int = None,
    process_parent_pid: int = None,
    process_parent_name: str = None,
    process_path: str = None,
    process_cmdline: str = None,
    process_signature: str = None,
    file_path: str = None,
    file_name: str = None,
    file_sha256: str = None,
    attack_type: str = None,
    attack_technique: str = None,
    attack_mitre: str = None,
    attack_confidence: float = 0.0,
    honeypot_triggered: bool = False,
    honeypot_resource: str = None,
    ml_prediction: str = None,
    ml_confidence: float = 0.0,
    ml_risk_score: float = 0.0,
    description: str = None,
    scenario_id: str = None,
    raw: dict = None,
) -> dict:
    """
    Create a unified security event.
    Only include fields that are actually observed — never fabricate.
    """
    event_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    event = {
        'event_id':  event_id,
        'timestamp': now,
        'event_type': event_type,
        'severity':  severity,
        'description': description or event_type,
        'scenario_id': scenario_id,

        'source': {
            'ip':        source_ip,
            'port':      source_port,
            'protocol':  source_protocol,
            'mac':       source_mac,       # None unless directly observable
            'hostname':  source_hostname,
            'interface': source_interface,
        },

        'destination': {
            'ip':       dest_ip,
            'port':     dest_port,
            'hostname': dest_hostname,
        },

        'process': {
            'name':       process_name,
            'pid':        process_pid,
            'parent_pid': process_parent_pid,
            'parent':     process_parent_name,
            'path':       process_path,
            'cmdline':    process_cmdline,
            'signature':  process_signature,
        },

        'file': {
            'path':   file_path,
            'name':   file_name,
            'sha256': file_sha256,
        },

        'attack': {
            'type':       attack_type,
            'technique':  attack_technique,
            'mitre':      attack_mitre,
            'confidence': attack_confidence,
        },

        'honeypot': {
            'triggered': honeypot_triggered,
            'resource':  honeypot_resource,
        },

        'ml': {
            'prediction': ml_prediction,
            'confidence': ml_confidence,
            'risk_score': ml_risk_score,
        },

        '_raw': raw or {},
    }

    return event


def event_hash(event: dict) -> str:
    """Deterministic SHA-256 hash of key event fields for deduplication & integrity."""
    key = {
        'event_type': event.get('event_type'),
        'timestamp':  event.get('timestamp'),
        'source_ip':  (event.get('source') or {}).get('ip'),
        'attack_type': (event.get('attack') or {}).get('type'),
        'file_name':  (event.get('file') or {}).get('name'),
    }
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()


def strip_nulls(d: dict) -> dict:
    """Remove None-valued keys for clean JSON serialization."""
    if not isinstance(d, dict):
        return d
    return {k: strip_nulls(v) for k, v in d.items() if v is not None}

"""
Forensic Evidence Preservation for CyberDefense-AI
After an incident, preserves a structured evidence bundle:
  - Event timeline
  - Process information
  - File hashes
  - Network indicators
  - Honeypot events
  - ML predictions
  - Risk score + factors
  - Response actions
  - Blockchain transaction info

Evidence bundles are stored locally.
A cryptographic hash of the bundle is recorded on-chain for integrity verification.
"""
import os
import json
import hashlib
from datetime import datetime

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'evidence')


def preserve_evidence(
    incident: dict,
    events:   list    = None,
    honeypot_events: list = None,
    quarantine_info: dict = None,
    blockchain_result: dict = None,
) -> dict:
    """
    Create and save an evidence bundle for an incident.
    Returns {'bundle_path': ..., 'evidence_hash': ...}
    """
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    now       = datetime.utcnow().isoformat()
    inc_id    = incident.get('id', 'unknown')
    timestamp = now.replace(':', '-').replace('.', '-')[:19]

    bundle = {
        'meta': {
            'bundle_version':  '1.0',
            'generated_at':    now,
            'incident_id':     inc_id,
            'platform':        'CyberDefense-AI',
            'integrity_note':  (
                'This evidence bundle is cryptographically hashed. '
                'The hash is recorded on blockchain for tamper detection. '
                'Verify with /api/evidence/verify endpoint.'
            ),
        },

        'incident_summary': {
            'id':             inc_id,
            'title':          incident.get('title'),
            'attack_type':    incident.get('attack_type'),
            'severity':       incident.get('severity'),
            'risk_score':     incident.get('risk_score'),
            'risk_level':     incident.get('risk_level'),
            'status':         incident.get('status'),
            'response':       incident.get('response'),
            'created_at':     incident.get('created_at'),
            'closed_at':      incident.get('closed_at'),
        },

        'attacker_info': {
            'source_ip':   incident.get('source_ip'),
            'source_port': incident.get('source_port'),
            'dest_ip':     incident.get('dest_ip'),
            'dest_port':   incident.get('dest_port'),
            'protocol':    incident.get('protocol'),
            'source_mac':  incident.get('source_mac'),
            'geo_info':    incident.get('geo_info'),
        },

        'process_info': {
            'process_name': incident.get('process_name'),
            'process_pid':  incident.get('process_pid'),
            'process_path': incident.get('process_path'),
        },

        'file_info': {
            'file_name':     incident.get('file_name'),
            'file_sha256':   incident.get('file_sha256'),
            'files_affected': incident.get('files_affected', 0),
        },

        'honeypot_events': honeypot_events or [],

        'ml_analysis': {
            'prediction':   incident.get('ml_prediction'),
            'confidence':   incident.get('ml_confidence'),
            'risk_factors': incident.get('risk_factors') or {},
        },

        'event_timeline': incident.get('timeline') or events or [],

        'response_actions': {
            'response':     incident.get('response'),
            'quarantine':   quarantine_info or {},
        },

        'blockchain': {
            'tx_hash':  (blockchain_result or {}).get('tx_hash'),
            'block':    (blockchain_result or {}).get('block'),
            'explorer': (blockchain_result or {}).get('explorer'),
            'mode':     (blockchain_result or {}).get('mode'),
            'note':     (
                'Evidence hash is stored on-chain. '
                'To verify: recompute SHA-256 of this bundle and compare with blockchain record.'
            ),
        },
    }

    # Compute bundle hash (deterministic — sort_keys=True)
    bundle_str    = json.dumps(bundle, sort_keys=True, default=str)
    evidence_hash = hashlib.sha256(bundle_str.encode()).hexdigest()
    bundle['meta']['evidence_hash'] = evidence_hash

    # Save
    filename   = f'evidence_{inc_id}_{timestamp}.json'
    filepath   = os.path.join(EVIDENCE_DIR, filename)
    with open(filepath, 'w') as f:
        json.dump(bundle, f, indent=2, default=str)

    print(f"🔒 Evidence preserved: {filename}")
    print(f"   Hash: {evidence_hash[:32]}...")

    return {
        'bundle_path':    filepath,
        'evidence_hash':  evidence_hash,
        'filename':       filename,
        'generated_at':   now,
        'incident_id':    inc_id,
    }


def verify_evidence(filepath: str, expected_hash: str) -> dict:
    """
    Recompute the evidence hash from the stored bundle and compare.
    Used to verify integrity against blockchain record.
    """
    if not os.path.exists(filepath):
        return {'verified': False, 'error': 'Evidence file not found'}

    try:
        with open(filepath) as f:
            bundle = json.load(f)

        # Remove the stored hash before recomputing
        stored_hash = bundle.get('meta', {}).pop('evidence_hash', None)
        computed_hash = hashlib.sha256(
            json.dumps(bundle, sort_keys=True, default=str).encode()
        ).hexdigest()

        # Restore it
        bundle['meta']['evidence_hash'] = stored_hash

        match = computed_hash == expected_hash
        return {
            'verified':        match,
            'computed_hash':   computed_hash,
            'expected_hash':   expected_hash,
            'stored_hash':     stored_hash,
            'integrity':       'INTACT' if match else 'TAMPERED',
        }
    except Exception as e:
        return {'verified': False, 'error': str(e)}


def list_evidence_bundles() -> list:
    """List all stored evidence bundles."""
    if not os.path.exists(EVIDENCE_DIR):
        return []
    bundles = []
    for fn in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
        if fn.startswith('evidence_') and fn.endswith('.json'):
            path = os.path.join(EVIDENCE_DIR, fn)
            size = os.path.getsize(path)
            bundles.append({
                'filename': fn,
                'path':     path,
                'size':     size,
                'modified': datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
            })
    return bundles


def get_evidence_bundle(incident_id: str) -> dict:
    """Load the most recent evidence bundle for a given incident."""
    if not os.path.exists(EVIDENCE_DIR):
        return {}
    for fn in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
        if fn.startswith(f'evidence_{incident_id}_') and fn.endswith('.json'):
            path = os.path.join(EVIDENCE_DIR, fn)
            try:
                with open(path) as f:
                    return json.load(f)
            except Exception:
                continue
    return {}

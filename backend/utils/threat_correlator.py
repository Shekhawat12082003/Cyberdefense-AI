"""
Threat Correlation Engine for CyberDefense-AI
Correlates multiple independent security events into high-confidence incidents.
Correlation dimensions: time proximity, process identity, source IP,
file activity, honeypot events, ML predictions, scenario ID.
"""
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

# Correlation window — events within this window are candidates for correlation
CORRELATION_WINDOW_SECONDS = 120

# Minimum number of signals to declare a correlated incident
MIN_SIGNALS_FOR_INCIDENT = 2


class CorrelatedIncident:
    def __init__(self, incident_id: str, first_event: dict):
        self.incident_id  = incident_id
        self.created_at   = datetime.utcnow()
        self.updated_at   = datetime.utcnow()
        self.events:  List[dict] = [first_event]
        self.scenario_id: Optional[str] = first_event.get('scenario_id')

        # Aggregated signals
        self.source_ips:       set = set()
        self.processes:        set = set()
        self.file_events:      int = 0
        self.honeypot_count:   int = 0
        self.ml_predictions:   list = []
        self.network_alerts:   list = []
        self.process_alerts:   list = []

        self._absorb(first_event)

    def _absorb(self, event: dict):
        """Extract signal info from a new event."""
        src = (event.get('source') or {}).get('ip')
        if src:
            self.source_ips.add(src)

        proc = (event.get('process') or {}).get('name')
        if proc:
            self.processes.add(proc)

        if (event.get('file') or {}).get('name'):
            self.file_events += 1

        if (event.get('honeypot') or {}).get('triggered'):
            self.honeypot_count += 1

        ml = event.get('ml') or {}
        if ml.get('prediction') and ml['prediction'] not in ('None', None, ''):
            self.ml_predictions.append(ml['prediction'])

        et = event.get('event_type', '')
        if 'NETWORK' in et.upper() or 'PORT_SCAN' in et.upper() or 'BRUTE' in et.upper():
            self.network_alerts.append(et)
        if 'PROCESS' in et.upper() or 'SUSPICIOUS' in et.upper():
            self.process_alerts.append(et)

    def add_event(self, event: dict):
        self.events.append(event)
        self.updated_at = datetime.utcnow()
        self._absorb(event)

    def signal_count(self) -> int:
        count = 0
        if self.source_ips:        count += 1
        if self.processes:         count += 1
        if self.file_events > 0:   count += 1
        if self.honeypot_count > 0: count += 1
        if self.ml_predictions:    count += 1
        if self.network_alerts:    count += 1
        return count

    def to_dict(self) -> dict:
        return {
            'incident_id':   self.incident_id,
            'created_at':    self.created_at.isoformat(),
            'updated_at':    self.updated_at.isoformat(),
            'scenario_id':   self.scenario_id,
            'event_count':   len(self.events),
            'signal_count':  self.signal_count(),
            'source_ips':    list(self.source_ips),
            'processes':     list(self.processes),
            'file_events':   self.file_events,
            'honeypot_count': self.honeypot_count,
            'ml_predictions': self.ml_predictions,
            'network_alerts': self.network_alerts,
            'process_alerts': self.process_alerts,
            'events':        self.events,
        }


class ThreatCorrelator:
    def __init__(self):
        self._lock = threading.Lock()
        # Active correlation buckets keyed by correlation_key
        self._buckets: dict = {}
        # Completed incidents keyed by incident_id
        self._incidents: dict = {}
        # Index: scenario_id → incident_id
        self._scenario_index: dict = {}
        # Callbacks
        self._callbacks: list = []

    def register_callback(self, fn):
        """Register a callback invoked when a new incident is correlated."""
        self._callbacks.append(fn)

    def ingest_event(self, event: dict) -> Optional[str]:
        """
        Ingest a security event. Returns incident_id if a new incident was
        created or an existing one was updated with enough signals.
        """
        now      = datetime.utcnow()
        key      = self._correlation_key(event)
        scenario = event.get('scenario_id')

        with self._lock:
            # Check if there's an active bucket for this key
            incident = self._buckets.get(key)

            if incident is None and scenario and scenario in self._scenario_index:
                # Same scenario — join that incident
                inc_id   = self._scenario_index[scenario]
                incident = self._incidents.get(inc_id)
                if incident:
                    # Check it's still within window
                    age = (now - incident.updated_at).total_seconds()
                    if age > CORRELATION_WINDOW_SECONDS * 2:
                        incident = None

            if incident is None:
                # New bucket
                inc_id   = str(uuid.uuid4())[:8]
                incident = CorrelatedIncident(inc_id, event)
                self._buckets[key] = incident
                self._incidents[inc_id] = incident
                if scenario:
                    self._scenario_index[scenario] = inc_id
            else:
                incident.add_event(event)

            # Expire old buckets
            expired = [k for k, v in self._buckets.items()
                       if (now - v.updated_at).total_seconds() > CORRELATION_WINDOW_SECONDS]
            for k in expired:
                del self._buckets[k]

        # Fire callbacks when threshold reached
        if incident.signal_count() >= MIN_SIGNALS_FOR_INCIDENT:
            for cb in self._callbacks:
                try:
                    cb(incident.to_dict())
                except Exception:
                    pass
            return incident.incident_id

        return None

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            return inc.to_dict() if inc else None

    def get_all_incidents(self, limit: int = 50) -> list:
        with self._lock:
            incs = sorted(
                self._incidents.values(),
                key=lambda i: i.updated_at,
                reverse=True
            )
            return [i.to_dict() for i in incs[:limit]]

    def get_incident_by_scenario(self, scenario_id: str) -> Optional[dict]:
        with self._lock:
            inc_id = self._scenario_index.get(scenario_id)
            if inc_id:
                inc = self._incidents.get(inc_id)
                return inc.to_dict() if inc else None
        return None

    def _correlation_key(self, event: dict) -> str:
        """
        Compute a correlation key — events sharing a key are grouped together.
        Priority: scenario_id → source_ip → process_pid
        """
        scenario = event.get('scenario_id')
        if scenario:
            return f'scenario:{scenario}'

        src_ip = (event.get('source') or {}).get('ip')
        if src_ip:
            return f'ip:{src_ip}'

        pid = (event.get('process') or {}).get('pid')
        if pid:
            return f'pid:{pid}'

        # Fallback — event type (will merge unrelated events but better than nothing)
        return f'type:{event.get("event_type", "unknown")}'


# ── Module-level singleton ────────────────────────────────
_correlator = ThreatCorrelator()


def get_correlator() -> ThreatCorrelator:
    return _correlator


def ingest(event: dict) -> Optional[str]:
    return _correlator.ingest_event(event)


def get_all_incidents(limit: int = 50) -> list:
    return _correlator.get_all_incidents(limit)


def get_incident(incident_id: str) -> Optional[dict]:
    return _correlator.get_incident(incident_id)

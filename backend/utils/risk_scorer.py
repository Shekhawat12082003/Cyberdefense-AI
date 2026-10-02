




"""
Transparent, configurable Risk Scorer.
Combines multiple signal types into a single 0-100 risk score.
Each contributing factor is tracked and returned for display.
Score bands: LOW 0-25, MODERATE 26-50, HIGH 51-75, CRITICAL 76-100
"""
from dataclasses import dataclass, field
from typing import List, Optional


# ── Default factor weights ────────────────────────────────
# For network-primary incidents these are recalibrated so a
# confirmed port scan or brute force gets a meaningful score.
DEFAULT_WEIGHTS = {
    'ml_prediction':     25,   # ML model classification
    'file_activity':     15,   # File modifications
    'honeypot':          25,   # Honeypot interaction (very strong signal)
    'network_anomaly':   25,   # Network attack (primary signal)
    'process_anomaly':   5,    # Suspicious process
    'correlation':       5,    # Multi-signal bonus
}

# Attack-type severity multipliers applied to network_anomaly weight.
# These ensure real attacks get proportional scores:
#   PORT_SCAN alone  → ~18  (LOW — recon only)
#   BRUTE_FORCE      → ~26  (MODERATE — active attack)
#   SYN_FLOOD        → ~26  (MODERATE — DoS attempt)
#   With HONEYPOT    → ~44  (MODERATE-HIGH)
#   With ML + all    → ~97  (CRITICAL)
ATTACK_SEVERITY_MULTIPLIER = {
    'BRUTE_FORCE': 1.15,   # Active auth attack — above MODERATE
    'PORT_SCAN':   0.80,   # Recon only
    'SYN_FLOOD':   1.15,   # Active DoS
    'DATA_EXFIL':  1.10,   # Data theft
    'C2_BEACON':   1.05,   # Active C2
    'NULL_SCAN':   0.75,   # Stealth recon
    'XMAS_SCAN':   0.75,   # Stealth recon
    'FIN_SCAN':    0.65,   # Stealth recon
}


@dataclass
class RiskFactor:
    name:        str
    weight:      float   # max possible contribution
    actual:      float   # actual contribution (0..weight)
    reason:      str
    confidence:  float   # 0-1

    @property
    def contribution(self) -> float:
        return round(self.actual * self.confidence, 2)


@dataclass
class RiskScore:
    raw_score:   float
    final_score: float           # clamped 0-100
    risk_level:  str
    factors:     List[RiskFactor] = field(default_factory=list)
    summary:     str = ''

    def to_dict(self) -> dict:
        return {
            'raw_score':   self.raw_score,
            'final_score': self.final_score,
            'risk_level':  self.risk_level,
            'summary':     self.summary,
            'factors': [
                {
                    'name':         f.name,
                    'weight':       f.weight,
                    'contribution': f.contribution,
                    'reason':       f.reason,
                    'confidence':   f.confidence,
                }
                for f in self.factors
            ]
        }


def calculate_risk(
    ml_prediction:    Optional[str]   = None,
    ml_confidence:    float           = 0.0,
    ml_score:         float           = 0.0,
    file_events:      int             = 0,
    honeypot_hit:     bool            = False,
    honeypot_count:   int             = 0,
    network_alert:    Optional[str]   = None,
    network_severity: str             = 'LOW',
    process_suspicious: bool          = False,
    process_risk:     str             = 'LOW',
    correlated_signals: int           = 0,
    weights:          Optional[dict]  = None,
) -> RiskScore:
    """
    Calculate transparent risk score from multiple signals.
    Returns RiskScore with all contributing factors.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    factors: List[RiskFactor] = []
    total = 0.0

    # ── ML Prediction factor ──────────────────────────────
    if ml_prediction:
        if ml_prediction.lower() == 'ransomware':
            ml_conf  = min(ml_confidence / 100.0, 1.0) if ml_confidence > 1 else ml_confidence
            ml_contr = w['ml_prediction']
            reason   = f'ML classified as Ransomware (confidence {ml_confidence:.1f}%)'
        elif ml_prediction.lower() == 'suspicious':
            ml_contr = w['ml_prediction'] * 0.55
            ml_conf  = min(ml_confidence / 100.0, 1.0) if ml_confidence > 1 else ml_confidence
            reason   = f'ML classified as Suspicious (confidence {ml_confidence:.1f}%)'
        elif ml_score > 70:
            ml_conf  = min(ml_score / 100.0, 1.0)
            ml_contr = w['ml_prediction']
            reason   = f'ML score {ml_score:.1f} above HIGH threshold'
        else:
            ml_conf  = 0.15
            ml_contr = w['ml_prediction'] * 0.1
            reason   = f'ML score {ml_score:.1f} (below HIGH threshold)'

        f = RiskFactor('ML Detection', w['ml_prediction'], ml_contr, reason, ml_conf)
        factors.append(f)
        total += f.contribution

    # ── File Activity factor ──────────────────────────────
    if file_events > 0:
        if file_events >= 50:
            fa_conf  = 0.95
            fa_contr = w['file_activity']
            reason   = f'Rapid file modifications: {file_events} files affected'
        elif file_events >= 10:
            fa_conf  = 0.75
            fa_contr = w['file_activity'] * 0.7
            reason   = f'Multiple file modifications: {file_events} files affected'
        else:
            fa_conf  = 0.5
            fa_contr = w['file_activity'] * 0.35
            reason   = f'File modification activity: {file_events} files'

        f = RiskFactor('File Activity', w['file_activity'], fa_contr, reason, fa_conf)
        factors.append(f)
        total += f.contribution

    # ── Honeypot factor ───────────────────────────────────
    if honeypot_hit or honeypot_count > 0:
        if honeypot_count >= 3:
            hp_conf  = 0.98
            hp_contr = w['honeypot']
            reason   = f'Multiple honeypot triggers: {honeypot_count} decoy resources accessed'
        elif honeypot_count >= 1:
            hp_conf  = 0.90
            hp_contr = w['honeypot'] * 0.85
            reason   = f'Honeypot triggered: {honeypot_count} decoy resource(s) accessed'
        else:
            hp_conf  = 0.80
            hp_contr = w['honeypot'] * 0.70
            reason   = 'Honeypot interaction detected'

        f = RiskFactor('Honeypot Trigger', w['honeypot'], hp_contr, reason, hp_conf)
        factors.append(f)
        total += f.contribution

    # ── Network Anomaly factor ────────────────────────────
    if network_alert:
        net_sev_map = {'CRITICAL': 1.0, 'HIGH': 0.90, 'MEDIUM': 0.65, 'LOW': 0.40}
        net_conf    = net_sev_map.get(network_severity.upper(), 0.6)

        # Apply attack-type multiplier
        attack_mult = ATTACK_SEVERITY_MULTIPLIER.get(network_alert.upper(), 0.75)
        net_contr   = w['network_anomaly'] * net_conf * attack_mult

        reason = f'Network attack: {network_alert.replace("_"," ")} (severity: {network_severity})'
        f = RiskFactor('Network Attack', w['network_anomaly'], net_contr, reason, net_conf)
        factors.append(f)
        total += f.contribution

    # ── Process Anomaly factor ────────────────────────────
    if process_suspicious:
        proc_map  = {'CRITICAL': 1.0, 'HIGH': 0.85, 'MEDIUM': 0.55, 'LOW': 0.25}
        proc_conf = proc_map.get(process_risk.upper(), 0.5)
        proc_contr = w['process_anomaly'] * proc_conf
        reason     = f'Suspicious process detected (risk: {process_risk})'
        f = RiskFactor('Process Anomaly', w['process_anomaly'], proc_contr, reason, proc_conf)
        factors.append(f)
        total += f.contribution

    # ── Correlation bonus factor ──────────────────────────
    if correlated_signals >= 2:
        corr_conf  = min(correlated_signals / 4.0, 1.0)
        corr_contr = w['correlation'] * corr_conf
        reason     = f'Multi-signal correlation: {correlated_signals} independent indicators'
        f = RiskFactor('Threat Correlation', w['correlation'], corr_contr, reason, corr_conf)
        factors.append(f)
        total += f.contribution

    # ── Final score ───────────────────────────────────────
    raw_score   = total
    final_score = min(round(raw_score, 1), 100.0)

    if final_score >= 76:
        risk_level = 'CRITICAL'
    elif final_score >= 51:
        risk_level = 'HIGH'
    elif final_score >= 26:
        risk_level = 'MODERATE'
    else:
        risk_level = 'LOW'

    # ── Summary ───────────────────────────────────────────
    top_factors = sorted(factors, key=lambda f: f.contribution, reverse=True)[:3]
    top_names   = [f.name for f in top_factors]
    summary = (
        f'Risk score {final_score}/100 ({risk_level}). '
        f'Primary factors: {", ".join(top_names)}.'
    )

    return RiskScore(
        raw_score=round(raw_score, 2),
        final_score=final_score,
        risk_level=risk_level,
        factors=factors,
        summary=summary,
    )

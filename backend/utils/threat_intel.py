"""
Threat Intelligence Enrichment — CyberDefense-AI
==================================================
Enriches attacker IPs and file hashes with data from:
  - AbuseIPDB  — IP reputation / abuse reports
  - Shodan     — open ports, services, vulnerabilities on attacker host
  - VirusTotal — file hash scanning (70+ AV engines)

All APIs are optional — falls back gracefully if keys are missing.
Keys set in backend/.env:
  ABUSEIPDB_API_KEY=...
  SHODAN_API_KEY=...
  VIRUSTOTAL_API_KEY=...

Rate limits (free tiers):
  AbuseIPDB  : 1000 checks/day
  Shodan     : 1 query/second, 100/month
  VirusTotal : 500 requests/day, 4/minute
"""

import os
import json
import hashlib
import threading
import requests
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Optional

# ── API keys from environment ─────────────────────────────
ABUSEIPDB_KEY   = os.getenv('ABUSEIPDB_API_KEY', '').strip()
SHODAN_KEY      = os.getenv('SHODAN_API_KEY', '').strip()
VIRUSTOTAL_KEY  = os.getenv('VIRUSTOTAL_API_KEY', '').strip()

# ── In-memory cache (IP → result, TTL 1 hour) ─────────────
_ip_cache:   dict = {}
_hash_cache: dict = {}
_cache_ttl        = timedelta(hours=1)
_lock             = threading.Lock()


def _cache_get(store: dict, key: str) -> Optional[dict]:
    with _lock:
        entry = store.get(key)
        if entry and datetime.utcnow() - entry['ts'] < _cache_ttl:
            return entry['data']
    return None


def _cache_set(store: dict, key: str, data: dict):
    with _lock:
        store[key] = {'data': data, 'ts': datetime.utcnow()}


# ══════════════════════════════════════════════════════════
# ABUSEIPDB
# ══════════════════════════════════════════════════════════

def check_abuseipdb(ip: str) -> dict:
    """
    Check IP reputation on AbuseIPDB.
    Returns abuse confidence score, report count, country, ISP.
    Free tier: 1000 checks/day.
    """
    if not ABUSEIPDB_KEY:
        return {'available': False, 'note': 'Set ABUSEIPDB_API_KEY in .env'}

    cached = _cache_get(_ip_cache, f'abuse_{ip}')
    if cached:
        return cached

    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={
                'Key':    ABUSEIPDB_KEY,
                'Accept': 'application/json',
            },
            params={
                'ipAddress':     ip,
                'maxAgeInDays':  90,
                'verbose':       '',
            },
            timeout=6,
        )
        if r.status_code == 200:
            d = r.json().get('data', {})
            result = {
                'available':         True,
                'ip':                d.get('ipAddress', ip),
                'abuse_score':       d.get('abuseConfidenceScore', 0),
                'total_reports':     d.get('totalReports', 0),
                'country_code':      d.get('countryCode', ''),
                'isp':               d.get('isp', 'Unknown'),
                'domain':            d.get('domain', ''),
                'is_tor':            d.get('isTor', False),
                'is_whitelist':      d.get('isWhitelisted', False),
                'last_reported':     d.get('lastReportedAt', ''),
                'usage_type':        d.get('usageType', ''),
                'risk_level':        _abuse_risk(d.get('abuseConfidenceScore', 0)),
                'source':            'abuseipdb.com',
                'url':               f'https://www.abuseipdb.com/check/{ip}',
            }
        elif r.status_code == 429:
            result = {'available': False, 'note': 'AbuseIPDB rate limit reached (1000/day)'}
        elif r.status_code == 401:
            result = {'available': False, 'note': 'AbuseIPDB: invalid API key'}
        else:
            result = {'available': False, 'note': f'AbuseIPDB error: {r.status_code}'}

        _cache_set(_ip_cache, f'abuse_{ip}', result)
        return result

    except Exception as e:
        err = {'available': False, 'note': f'AbuseIPDB request failed: {e}'}
        _cache_set(_ip_cache, f'abuse_{ip}', err)
        return err


def _abuse_risk(score: int) -> str:
    if score >= 75:  return 'CRITICAL'
    if score >= 50:  return 'HIGH'
    if score >= 25:  return 'MEDIUM'
    if score > 0:    return 'LOW'
    return 'CLEAN'


# ══════════════════════════════════════════════════════════
# SHODAN
# ══════════════════════════════════════════════════════════

def check_shodan(ip: str) -> dict:
    """
    Look up attacker host on Shodan.
    Returns open ports, running services, OS, CVEs, hostnames.
    Free tier: 1 query/second, 100/month.
    """
    if not SHODAN_KEY:
        return {'available': False, 'note': 'Set SHODAN_API_KEY in .env'}

    cached = _cache_get(_ip_cache, f'shodan_{ip}')
    if cached:
        return cached

    try:
        r = requests.get(
            f'https://api.shodan.io/shodan/host/{ip}',
            params={'key': SHODAN_KEY},
            timeout=8,
        )

        if r.status_code == 200:
            d = r.json()

            # Extract open ports and services
            ports = d.get('ports', [])
            services = []
            for item in d.get('data', [])[:10]:   # cap at 10 services
                svc = {
                    'port':      item.get('port'),
                    'transport': item.get('transport', 'tcp'),
                    'product':   item.get('product', ''),
                    'version':   item.get('version', ''),
                    'banner':    (item.get('data', '') or '')[:120],
                }
                services.append(svc)

            # CVEs
            vulns = list(d.get('vulns', {}).keys())[:10]   # cap at 10 CVEs

            result = {
                'available':    True,
                'ip':           ip,
                'org':          d.get('org', 'Unknown'),
                'isp':          d.get('isp', 'Unknown'),
                'os':           d.get('os', 'Unknown'),
                'country':      d.get('country_name', ''),
                'city':         d.get('city', ''),
                'hostnames':    d.get('hostnames', [])[:5],
                'tags':         d.get('tags', []),
                'open_ports':   ports,
                'port_count':   len(ports),
                'services':     services,
                'cves':         vulns,
                'cve_count':    len(vulns),
                'last_update':  d.get('last_update', ''),
                'risk_note':    _shodan_risk(ports, vulns),
                'source':       'shodan.io',
                'url':          f'https://www.shodan.io/host/{ip}',
            }

        elif r.status_code == 404:
            result = {
                'available': True,
                'ip':        ip,
                'note':      'No Shodan data for this IP',
                'open_ports': [],
                'services':  [],
                'cves':      [],
                'source':    'shodan.io',
            }
        elif r.status_code == 401:
            result = {'available': False, 'note': 'Shodan: invalid API key'}
        elif r.status_code == 429:
            result = {'available': False, 'note': 'Shodan rate limit reached'}
        else:
            result = {'available': False, 'note': f'Shodan error: {r.status_code}'}

        _cache_set(_ip_cache, f'shodan_{ip}', result)
        return result

    except Exception as e:
        err = {'available': False, 'note': f'Shodan request failed: {e}'}
        _cache_set(_ip_cache, f'shodan_{ip}', err)
        return err


def _shodan_risk(ports: list, cves: list) -> str:
    notes = []
    if cves:
        notes.append(f'{len(cves)} known CVE(s): {", ".join(cves[:3])}')
    dangerous = {22, 23, 3389, 5900, 445, 21, 25, 3306, 5432, 27017, 6379}
    exposed   = [p for p in ports if p in dangerous]
    if exposed:
        names = {22:'SSH',23:'Telnet',3389:'RDP',5900:'VNC',445:'SMB',
                 21:'FTP',25:'SMTP',3306:'MySQL',5432:'Postgres',
                 27017:'MongoDB',6379:'Redis'}
        notes.append(f'Exposed: {", ".join(names.get(p,str(p)) for p in exposed[:5])}')
    return ' | '.join(notes) if notes else 'No known threats'


# ══════════════════════════════════════════════════════════
# VIRUSTOTAL
# ══════════════════════════════════════════════════════════

def check_virustotal_hash(file_hash: str) -> dict:
    """
    Check file hash (MD5/SHA1/SHA256) on VirusTotal.
    Returns detection count, engine results, malware family.
    Free tier: 500 requests/day, 4/minute.
    """
    if not VIRUSTOTAL_KEY:
        return {'available': False, 'note': 'Set VIRUSTOTAL_API_KEY in .env'}

    if not file_hash or len(file_hash) < 16:
        return {'available': False, 'note': 'Invalid hash'}

    cached = _cache_get(_hash_cache, file_hash)
    if cached:
        return cached

    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_hash}',
            headers={'x-apikey': VIRUSTOTAL_KEY},
            timeout=10,
        )

        if r.status_code == 200:
            d     = r.json().get('data', {})
            attrs = d.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            results = attrs.get('last_analysis_results', {})

            malicious   = stats.get('malicious', 0)
            suspicious  = stats.get('suspicious', 0)
            total       = sum(stats.values())
            detections  = malicious + suspicious

            # Top detected names
            detected_by = [
                {'engine': eng, 'result': res.get('result', ''), 'category': res.get('category', '')}
                for eng, res in results.items()
                if res.get('category') in ('malicious', 'suspicious')
            ][:10]

            # Most common malware name
            names = [r['result'] for r in detected_by if r['result']]
            popular_name = max(set(names), key=names.count) if names else ''

            result = {
                'available':       True,
                'hash':            file_hash,
                'malicious':       malicious,
                'suspicious':      suspicious,
                'undetected':      stats.get('undetected', 0),
                'total_engines':   total,
                'detection_rate':  round((detections / total * 100), 1) if total > 0 else 0,
                'popular_name':    popular_name,
                'detected_by':     detected_by,
                'file_type':       attrs.get('type_description', ''),
                'file_size':       attrs.get('size', 0),
                'first_seen':      attrs.get('first_submission_date', ''),
                'last_seen':       attrs.get('last_analysis_date', ''),
                'verdict':         _vt_verdict(malicious, total),
                'source':          'virustotal.com',
                'url':             f'https://www.virustotal.com/gui/file/{file_hash}',
            }

        elif r.status_code == 404:
            result = {
                'available':  True,
                'hash':       file_hash,
                'note':       'File not found in VirusTotal database',
                'malicious':  0,
                'verdict':    'UNKNOWN',
                'source':     'virustotal.com',
                'url':        f'https://www.virustotal.com/gui/file/{file_hash}',
            }
        elif r.status_code == 401:
            result = {'available': False, 'note': 'VirusTotal: invalid API key'}
        elif r.status_code == 429:
            result = {'available': False, 'note': 'VirusTotal rate limit (4/min or 500/day)'}
        else:
            result = {'available': False, 'note': f'VirusTotal error: {r.status_code}'}

        _cache_set(_hash_cache, file_hash, result)
        return result

    except Exception as e:
        err = {'available': False, 'note': f'VirusTotal request failed: {e}'}
        _cache_set(_hash_cache, file_hash, err)
        return err


def check_virustotal_url(url_to_check: str) -> dict:
    """Check a URL on VirusTotal."""
    if not VIRUSTOTAL_KEY:
        return {'available': False, 'note': 'Set VIRUSTOTAL_API_KEY in .env'}

    import base64
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip('=')

    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': VIRUSTOTAL_KEY},
            timeout=10,
        )
        if r.status_code == 200:
            d     = r.json().get('data', {})
            attrs = d.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            mal   = stats.get('malicious', 0)
            total = sum(stats.values())
            return {
                'available':      True,
                'url':            url_to_check,
                'malicious':      mal,
                'total_engines':  total,
                'detection_rate': round((mal / total * 100), 1) if total > 0 else 0,
                'verdict':        _vt_verdict(mal, total),
                'categories':     attrs.get('categories', {}),
                'source':         'virustotal.com',
            }
        return {'available': False, 'note': f'VT URL check error: {r.status_code}'}
    except Exception as e:
        return {'available': False, 'note': str(e)}


def _vt_verdict(malicious: int, total: int) -> str:
    if total == 0:          return 'UNKNOWN'
    pct = malicious / total * 100
    if pct >= 50:           return 'MALICIOUS'
    if pct >= 10:           return 'SUSPICIOUS'
    if malicious > 0:       return 'LOW_RISK'
    return 'CLEAN'


# ══════════════════════════════════════════════════════════
# COMBINED ENRICHMENT
# ══════════════════════════════════════════════════════════

def enrich_ip(ip: str, background: bool = True) -> dict:
    """
    Full IP enrichment: AbuseIPDB + Shodan.
    Returns combined threat intelligence.

    Parameters
    ----------
    ip : str
        IP address to enrich
    background : bool
        If True, runs in a background thread and returns immediately.
        If False, blocks until complete (for API endpoints).
    """
    from utils.geo_lookup import is_private_ip

    if is_private_ip(ip):
        return {
            'ip':        ip,
            'type':      'private',
            'note':      'Private/local IP — no external lookup',
            'abuseipdb': {'available': False, 'note': 'Private IP'},
            'shodan':    {'available': False, 'note': 'Private IP'},
        }

    if background:
        # Non-blocking — caller gets result via callback or polls later
        result = {'ip': ip, 'status': 'enriching'}
        threading.Thread(target=lambda: _do_enrich_ip(ip), daemon=True).start()
        return result

    return _do_enrich_ip(ip)


def _do_enrich_ip(ip: str) -> dict:
    abuse  = check_abuseipdb(ip)
    shodan = check_shodan(ip)

    # Compute combined risk
    combined_risk = 'LOW'
    risk_factors  = []

    if abuse.get('available'):
        score = abuse.get('abuse_score', 0)
        if score >= 75:
            combined_risk = 'CRITICAL'
            risk_factors.append(f'AbuseIPDB: {score}% confidence ({abuse.get("total_reports",0)} reports)')
        elif score >= 25:
            combined_risk = 'HIGH'
            risk_factors.append(f'AbuseIPDB: {score}% abuse confidence')
        elif score > 0:
            combined_risk = 'MEDIUM'
            risk_factors.append(f'AbuseIPDB: low abuse score ({score}%)')

    if shodan.get('available') and shodan.get('cve_count', 0) > 0:
        if combined_risk not in ('CRITICAL',):
            combined_risk = 'HIGH'
        risk_factors.append(f'Shodan: {shodan["cve_count"]} CVEs')

    result = {
        'ip':            ip,
        'combined_risk': combined_risk,
        'risk_factors':  risk_factors,
        'abuseipdb':     abuse,
        'shodan':        shodan,
        'enriched_at':   datetime.utcnow().isoformat(),
    }
    _cache_set(_ip_cache, f'enriched_{ip}', result)
    return result


def enrich_file(file_hash: str) -> dict:
    """VirusTotal check for a file hash."""
    return check_virustotal_hash(file_hash)


def get_enrichment_status() -> dict:
    """Return which APIs are configured."""
    return {
        'abuseipdb':   {'configured': bool(ABUSEIPDB_KEY),  'service': 'abuseipdb.com'},
        'shodan':      {'configured': bool(SHODAN_KEY),     'service': 'shodan.io'},
        'virustotal':  {'configured': bool(VIRUSTOTAL_KEY), 'service': 'virustotal.com'},
        'any_active':  any([ABUSEIPDB_KEY, SHODAN_KEY, VIRUSTOTAL_KEY]),
    }

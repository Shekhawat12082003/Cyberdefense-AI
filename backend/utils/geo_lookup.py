"""
IP Geolocation Lookup
Primary:   ipinfo.io  (HTTPS, free 50k/month, more accurate)
           Set IPINFO_TOKEN in .env for higher rate limits (free at ipinfo.io)
Fallback:  ip-api.com (free, no key, HTTP only, 45 req/min)
Always labels results as APPROXIMATE — never fabricates location data.
Private/local IPs are identified without any lookup attempt.
"""
import os
import ipaddress
import requests
from functools import lru_cache

IPINFO_TOKEN = os.getenv('IPINFO_TOKEN', '').strip()

# RFC 1918 + loopback + link-local
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]


def is_private_ip(ip: str) -> bool:
    """Return True for RFC 1918 / loopback / link-local addresses."""
    if not ip or ip in ('local', 'unknown', '', 'N/A'):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True


@lru_cache(maxsize=256)
def _cached_lookup(ip: str) -> dict:
    """Cached lookup — avoids repeated calls for same IP within process lifetime."""
    # Try ipinfo.io first (HTTPS, more accurate, free 50k/month)
    result = _lookup_ipinfo(ip)
    if result:
        return result
    # Fallback to ip-api.com
    return _lookup_ipapi(ip)


def _lookup_ipinfo(ip: str) -> dict:
    """ipinfo.io — HTTPS, free 50k/month, optional token for higher limits."""
    try:
        url    = f'https://ipinfo.io/{ip}/json'
        params = {'token': IPINFO_TOKEN} if IPINFO_TOKEN else {}
        r = requests.get(url, params=params, timeout=5)
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get('bogon'):
            return None

        lat, lon = None, None
        if d.get('loc'):
            try:
                lat, lon = [float(x) for x in d['loc'].split(',')]
            except Exception:
                pass

        return {
            'ip':          d.get('ip', ip),
            'country':     d.get('country', 'Unknown'),
            'region':      d.get('region', 'Unknown'),
            'city':        d.get('city', 'Unknown'),
            'lat':         lat,
            'lon':         lon,
            'isp':         d.get('org', 'Unknown'),
            'asn':         d.get('org', '').split(' ')[0] if d.get('org') else 'Unknown',
            'org':         d.get('org', 'Unknown'),
            'timezone':    d.get('timezone', 'Unknown'),
            'hostname':    d.get('hostname', ''),
            'approximate': True,
            'source':      'ipinfo.io',
        }
    except Exception:
        return None


def _lookup_ipapi(ip: str) -> dict:
    """ip-api.com fallback — HTTP only, free, 45 req/min."""
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'status,country,regionName,city,lat,lon,isp,as,org,timezone,query'},
            timeout=4,
        )
        data = r.json()
        if data.get('status') != 'success':
            return None
        return {
            'ip':          data.get('query', ip),
            'country':     data.get('country', 'Unknown'),
            'region':      data.get('regionName', 'Unknown'),
            'city':        data.get('city', 'Unknown'),
            'lat':         data.get('lat'),
            'lon':         data.get('lon'),
            'isp':         data.get('isp', 'Unknown'),
            'asn':         data.get('as', 'Unknown'),
            'org':         data.get('org', 'Unknown'),
            'timezone':    data.get('timezone', 'Unknown'),
            'approximate': True,
            'source':      'ip-api.com',
        }
    except Exception:
        return None


def geolocate(ip: str) -> dict:
    """
    Return geolocation info for an IP address.
    Always includes 'type' field:
      - 'private'     → local/RFC1918 address
      - 'approximate' → external, lookup succeeded
      - 'unknown'     → lookup failed
    Never fabricates location data.
    """
    if is_private_ip(ip):
        return {
            'ip':    ip,
            'type':  'private',
            'label': 'Local / Private Address',
        }

    result = _cached_lookup(ip)
    if result:
        result['type'] = 'approximate'
        return result

    return {
        'ip':    ip,
        'type':  'unknown',
        'label': 'Location: Unknown',
    }


def format_geo_display(geo: dict) -> dict:
    """Format geolocation for frontend display with appropriate disclaimers."""
    if not geo:
        return {'display': 'Unknown', 'type': 'unknown'}

    t = geo.get('type', 'unknown')

    if t == 'private':
        return {
            'type':    'private',
            'display': 'LOCAL NETWORK',
            'label':   'Local / Private Address',
            'note':    'Not routable on internet',
        }

    if t == 'approximate':
        parts        = [geo.get('city'), geo.get('region'), geo.get('country')]
        location_str = ', '.join(p for p in parts if p and p != 'Unknown')
        return {
            'type':     'approximate',
            'display':  location_str or 'Unknown',
            'country':  geo.get('country'),
            'region':   geo.get('region'),
            'city':     geo.get('city'),
            'lat':      geo.get('lat'),
            'lon':      geo.get('lon'),
            'isp':      geo.get('isp'),
            'asn':      geo.get('asn'),
            'org':      geo.get('org'),
            'timezone': geo.get('timezone'),
            'hostname': geo.get('hostname', ''),
            'source':   geo.get('source', 'ipinfo.io'),
            'note':     'APPROXIMATE IP GEOLOCATION — does not represent exact physical location',
        }

    return {
        'type':    'unknown',
        'display': 'Unknown',
        'note':    'Geolocation unavailable',
    }

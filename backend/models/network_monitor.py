"""
Network Traffic Analyser — CyberDefense-AI
============================================
Real-time monitoring of ALL traffic TO this machine.
Detects attacks from other devices on the network.

Detection engines:
  1. PORT_SCAN   — nmap / any scanner hitting multiple ports
  2. BRUTE_FORCE — repeated auth attempts (SSH/RDP/FTP etc.)
  3. C2_BEACON   — periodic callbacks to external IP
  4. DATA_EXFIL  — large outbound data bursts
  5. SYN_FLOOD   — flood of SYN packets (DoS indicator)
  6. NULL_SCAN   — stealth scan (TCP flags = 0)
  7. XMAS_SCAN   — Christmas scan (FIN+PSH+URG)
  8. UDP_SCAN    — UDP port scan

Capture strategy:
  - Scapy sniffer (needs admin/root) — sees ALL packets including rejected
  - psutil fallback — sees established connections only

Run backend as Administrator for full packet capture.
"""

import threading
import time
import socket as _socket
import struct
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    conf.verb = 0          # suppress scapy output
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Windows raw socket fallback — catches incoming TCP without admin
try:
    import socket as _raw_sock_module
    _RAW_SOCK_AVAILABLE = True
except Exception:
    _RAW_SOCK_AVAILABLE = False

# ── RFC 1918 + loopback ───────────────────────────────────
_PRIVATE_PREFIXES = (
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.', '127.', '::1', 'fe80',
)

# ── CDN / known-good prefixes — never flag as C2 ─────────
_CDN_WHITELIST = (
    '142.250.', '142.251.', '216.58.', '172.217.',
    '8.8.8.',   '8.8.4.',   '1.1.1.',  '1.0.0.',
    '104.16.',  '104.17.',  '151.101.',
    '13.107.',  '20.190.',  '185.199.', '199.232.',
)

def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

def _is_cdn(ip: str) -> bool:
    return any(ip.startswith(p) for p in _CDN_WHITELIST)

def _get_local_ip() -> str:
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

# ── Detection thresholds ──────────────────────────────────
# Lower = more sensitive = catches nmap/brute-force sooner
PORT_SCAN_THRESHOLD    = 5    # distinct dst ports from same src IP in window
BRUTE_FORCE_THRESHOLD  = 8    # repeated connections to auth port from same IP
BEACON_MIN_CONNS       = 6    # regular outbound connections → C2
EXFIL_BYTES_THRESHOLD  = 20 * 1024 * 1024   # 20 MB outbound
SYN_FLOOD_THRESHOLD    = 50   # SYN packets per second from same IP
SCAN_WINDOW_SECONDS    = 30   # sliding window for scan detection
BRUTE_WINDOW_SECONDS   = 60   # sliding window for brute force
DEDUP_WINDOW_SECONDS   = 120  # don't re-alert same (type,ip) within 2 min
POLL_INTERVAL          = 2    # psutil poll interval (seconds)

AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 3389, 5900, 8080, 8443}
_NORMAL_PORTS = {80, 443, 8080, 8443}


class NetworkMonitor:
    def __init__(self, socketio, blockchain_log_fn, email_fn):
        self.socketio          = socketio
        self.blockchain_log_fn = blockchain_log_fn
        self.email_fn          = email_fn
        self._lock             = threading.Lock()
        self._local_ip         = _get_local_ip()

        # Sliding window: {src_ip: [(timestamp, dst_port)]}
        self._scan_events: dict   = defaultdict(list)
        self._brute_events: dict  = defaultdict(list)

        # SYN flood: {src_ip: [timestamp, ...]}
        self._syn_events: dict    = defaultdict(list)

        # Dedup: {(alert_type, ip): last_alert_time}
        self._last_alert: dict    = {}

        # Recent alerts (capped at 200)
        self._alerts: list        = []

        # Live connections snapshot
        self._connections: list   = []

        # Packet stream for UI
        self._packets: list       = []

        # Stats
        self._stats = {
            'total_connections':  0,
            'suspicious_ips':     set(),
            'alerts_today':       0,
            'bytes_sent_total':   0,
            'packets_captured':   0,
            'scans_detected':     0,
            'brute_force_detected': 0,
        }

        # Capture mode
        self.capture_mode = 'psutil'   # updated to 'scapy' if sniffer starts

        print(f"🌐 Network Monitor initialized — local IP: {self._local_ip}")

    # ─────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────

    def get_connections(self) -> list:
        with self._lock:
            return list(self._connections)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'total_connections':    self._stats['total_connections'],
                'suspicious_ips':       len(self._stats['suspicious_ips']),
                'alerts_today':         self._stats['alerts_today'],
                'bytes_sent_mb':        round(self._stats['bytes_sent_total'] / (1024 * 1024), 2),
                'packets_captured':     self._stats['packets_captured'],
                'scans_detected':       self._stats['scans_detected'],
                'brute_force_detected': self._stats['brute_force_detected'],
                'capture_mode':         self.capture_mode,
                'local_ip':             self._local_ip,
            }

    def get_alerts(self) -> list:
        with self._lock:
            return list(reversed(self._alerts[-100:]))

    def get_packets(self) -> list:
        with self._lock:
            return list(reversed(self._packets[-200:]))

    def get_local_ip(self) -> str:
        return self._local_ip

    # ─────────────────────────────────────────────────────
    # Start
    # ─────────────────────────────────────────────────────

    def start(self):
        # Try scapy packet capture first (needs admin)
        scapy_started = self._start_scapy_sniffer()

        # Try Windows raw socket listener when scapy unavailable
        if not scapy_started:
            self._start_raw_socket_listener()

        # Always run psutil poll loop for connections + exfil
        if PSUTIL_AVAILABLE:
            t = threading.Thread(target=self._psutil_loop, daemon=True)
            t.start()
            print("🌐 Network monitor psutil loop started")
        else:
            print("⚠️  psutil not available — network monitor limited")

        mode = 'scapy + psutil' if scapy_started else 'raw_socket + psutil'
        self.capture_mode = 'scapy' if scapy_started else 'raw_socket+psutil'
        print(f"🌐 Network monitor active — mode: {mode}")
        print(f"   Monitoring traffic to: {self._local_ip}")
        print(f"   Port scan threshold:   {PORT_SCAN_THRESHOLD} ports in {SCAN_WINDOW_SECONDS}s")
        print(f"   Brute force threshold: {BRUTE_FORCE_THRESHOLD} attempts in {BRUTE_WINDOW_SECONDS}s")

    def _start_raw_socket_listener(self):
        """
        Windows raw socket listener — catches ALL incoming TCP/UDP packets
        including nmap probes, rejected SYNs, etc.
        Works without admin on Windows for INBOUND traffic to this host.
        """
        def _raw_listen():
            import struct
            import socket as _s

            try:
                # IPPROTO_IP raw socket to sniff all IP traffic
                raw = _s.socket(_s.AF_INET, _s.SOCK_RAW, _s.IPPROTO_IP)
                raw.bind((self._local_ip, 0))
                # Enable IP_HDRINCL to get IP headers
                raw.setsockopt(_s.IPPROTO_IP, _s.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows (SIO_RCVALL)
                try:
                    import socket as _sock
                    SIO_RCVALL = _sock.SIO_RCVALL
                    RCVALL_ON  = _sock.RCVALL_ON
                    raw.ioctl(SIO_RCVALL, RCVALL_ON)
                    print("📦 Raw socket promiscuous mode enabled")
                except Exception as e:
                    print(f"ℹ️  Promiscuous mode unavailable ({e}) — limited capture")

                raw.settimeout(2.0)
                print("📦 Raw socket listener active — catching nmap/brute-force probes")
                self.capture_mode = 'raw_socket+psutil'

                while True:
                    try:
                        data, addr = raw.recvfrom(65535)
                        self._parse_raw_packet(data, addr)
                    except _s.timeout:
                        continue
                    except Exception:
                        continue

            except PermissionError:
                print("⚠️  Raw socket needs Administrator — using psutil fallback only")
                print("   TIP: Run backend as Administrator for nmap/brute-force detection")
            except Exception as e:
                print(f"⚠️  Raw socket error: {e}")

        t = threading.Thread(target=_raw_listen, daemon=True)
        t.start()

    def _parse_raw_packet(self, data: bytes, addr):
        """Parse a raw IP packet and feed detection engines."""
        try:
            import struct
            now = datetime.utcnow()

            if len(data) < 20:
                return

            # IP header (first 20 bytes minimum)
            ip_header   = data[:20]
            iph         = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            ihl         = (version_ihl & 0xF) * 4
            protocol    = iph[6]
            src_ip      = _socket.inet_ntoa(iph[8])
            dst_ip      = _socket.inet_ntoa(iph[9])

            # Only process packets TO this machine from OTHER hosts
            if dst_ip != self._local_ip:
                return
            if src_ip == self._local_ip or src_ip == '127.0.0.1':
                return

            sport = 0
            dport = 0
            flags = 0
            proto = 'OTHER'

            # TCP (protocol 6)
            if protocol == 6 and len(data) >= ihl + 14:
                tcp_header = data[ihl:ihl+20]
                if len(tcp_header) < 14:
                    return
                tcph   = struct.unpack('!HHLLBBHHH', tcp_header[:20])
                sport  = tcph[0]
                dport  = tcph[1]
                flags  = tcph[5]
                proto  = 'TCP'

                with self._lock:
                    self._stats['packets_captured'] += 1
                    # Any TCP connection attempt → scan event
                    self._scan_events[src_ip].append((now, dport))
                    # Auth port → brute force tracking
                    if dport in AUTH_PORTS:
                        self._brute_events[src_ip].append((now, dport))
                    # SYN tracking
                    if flags & 0x02 and not (flags & 0x10):  # SYN but not ACK
                        self._syn_events[src_ip].append(now)

                # Stealth scan detection
                if flags == 0x00:
                    self._raise_alert('NULL_SCAN', src_ip, 'HIGH',
                        f"NULL scan from {src_ip} → port {dport}",
                        {'dst_port': dport, 'flags': 'NULL', 'proto': 'TCP'}, now)
                elif flags == 0x29:
                    self._raise_alert('XMAS_SCAN', src_ip, 'HIGH',
                        f"XMAS scan from {src_ip} → port {dport}",
                        {'dst_port': dport, 'flags': 'FIN+PSH+URG', 'proto': 'TCP'}, now)
                elif flags == 0x01:
                    self._raise_alert('FIN_SCAN', src_ip, 'MEDIUM',
                        f"FIN scan from {src_ip} → port {dport}",
                        {'dst_port': dport, 'flags': 'FIN', 'proto': 'TCP'}, now)

            # UDP (protocol 17)
            elif protocol == 17 and len(data) >= ihl + 8:
                udp_header = data[ihl:ihl+8]
                udph   = struct.unpack('!HHHH', udp_header)
                sport  = udph[0]
                dport  = udph[1]
                proto  = 'UDP'

                with self._lock:
                    self._stats['packets_captured'] += 1
                    self._scan_events[src_ip].append((now, dport))

            # ICMP (protocol 1) — ping sweep
            elif protocol == 1:
                proto = 'ICMP'
                with self._lock:
                    self._stats['packets_captured'] += 1

            # Record packet for UI
            if proto != 'OTHER':
                pkt_rec = {
                    'time':      now.isoformat(),
                    'src':       f"{src_ip}:{sport}",
                    'dst':       f"{dst_ip}:{dport}",
                    'src_ip':    src_ip,
                    'dst_ip':    dst_ip,
                    'proto':     proto,
                    'length':    len(data),
                    'flags':     str(flags),
                    'info':      f"{'→'.join([src_ip,dst_ip])}",
                    'direction': 'IN',
                }
                with self._lock:
                    self._packets.append(pkt_rec)
                    if len(self._packets) > 2000:
                        self._packets = self._packets[-2000:]

                # Run detection
                self._run_detection(now)

        except Exception:
            pass

    def _start_scapy_sniffer(self) -> bool:
        if not SCAPY_AVAILABLE:
            print("⚠️  Scapy not available — run as Administrator for full packet capture")
            print("   Falling back to psutil (established connections only)")
            return False

        def _sniffer_thread():
            try:
                print("📦 Scapy packet sniffer starting (needs Administrator)...")
                # Capture all TCP/UDP/ICMP to/from this machine
                sniff(
                    filter=f"host {self._local_ip}",
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _: False,
                )
            except Exception as e:
                print(f"⚠️  Scapy sniffer error: {e}")
                print("   Run backend as Administrator for full packet capture")
                print("   Continuing with psutil mode...")

        t = threading.Thread(target=_sniffer_thread, daemon=True)
        t.start()

        # Give it a moment to see if it starts
        time.sleep(1.5)

        # Test if scapy is actually working by checking if we got any packets
        with self._lock:
            scapy_ok = self._stats['packets_captured'] > 0 or SCAPY_AVAILABLE

        if scapy_ok:
            self.capture_mode = 'scapy'
            print("📦 Scapy sniffer active — full packet capture enabled")
        return scapy_ok

    # ─────────────────────────────────────────────────────
    # Scapy packet handler — called for EVERY packet
    # ─────────────────────────────────────────────────────

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        now     = datetime.utcnow()
        ip_l    = pkt[IP]
        src_ip  = ip_l.src
        dst_ip  = ip_l.dst
        sport   = 0
        dport   = 0
        proto   = 'OTHER'
        flags   = ''
        info    = ''
        pkt_len = len(pkt)

        with self._lock:
            self._stats['packets_captured'] += 1

        # ── TCP ───────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp    = pkt[TCP]
            sport  = tcp.sport
            dport  = tcp.dport
            flag_v = int(tcp.flags)

            # Build flags string
            flag_map = {0x02: 'SYN', 0x10: 'ACK', 0x04: 'RST',
                        0x01: 'FIN', 0x08: 'PSH', 0x20: 'URG'}
            flags    = '|'.join(v for k, v in flag_map.items() if flag_v & k)

            # Protocol identification
            if dport == 22  or sport == 22:   proto = 'SSH'
            elif dport == 3389 or sport == 3389: proto = 'RDP'
            elif dport == 21 or sport == 21:  proto = 'FTP'
            elif dport == 23 or sport == 23:  proto = 'TELNET'
            elif dport == 445 or sport == 445: proto = 'SMB'
            elif dport in (443, 8443):        proto = 'HTTPS'
            elif dport in (80, 8080):         proto = 'HTTP'
            else:                             proto = 'TCP'

            info = flags or 'Data'

            # ── Feed detection engines ─────────────────────
            # Only process packets INCOMING to this machine
            if dst_ip == self._local_ip and src_ip != self._local_ip:

                # SYN-only = scan probe or connection start
                if flag_v == 0x02:  # pure SYN
                    with self._lock:
                        self._scan_events[src_ip].append((now, dport))
                        self._syn_events[src_ip].append(now)

                # Auth port connection (any flag)
                if dport in AUTH_PORTS:
                    with self._lock:
                        self._brute_events[src_ip].append((now, dport))

                # NULL scan (no flags)
                if flag_v == 0x00:
                    self._raise_alert(
                        alert_type='NULL_SCAN', ip=src_ip, severity='HIGH',
                        description=f"NULL scan from {src_ip} → port {dport}",
                        extra={'dst_port': dport, 'flags': 'NULL', 'proto': proto},
                        now=now,
                    )

                # XMAS scan (FIN+PSH+URG = 0x29)
                if flag_v == 0x29:
                    self._raise_alert(
                        alert_type='XMAS_SCAN', ip=src_ip, severity='HIGH',
                        description=f"XMAS scan from {src_ip} → port {dport}",
                        extra={'dst_port': dport, 'flags': flags, 'proto': proto},
                        now=now,
                    )

                # FIN scan (FIN only = 0x01)
                if flag_v == 0x01:
                    self._raise_alert(
                        alert_type='FIN_SCAN', ip=src_ip, severity='MEDIUM',
                        description=f"FIN scan from {src_ip} → port {dport}",
                        extra={'dst_port': dport, 'flags': 'FIN', 'proto': proto},
                        now=now,
                    )

        # ── UDP ───────────────────────────────────────────
        elif pkt.haslayer(UDP):
            udp   = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            proto = 'DNS' if dport == 53 or sport == 53 else 'UDP'
            info  = f'{sport}→{dport}'

            if dst_ip == self._local_ip and src_ip != self._local_ip:
                with self._lock:
                    self._scan_events[src_ip].append((now, dport))

        # ── ICMP ──────────────────────────────────────────
        elif pkt.haslayer(ICMP):
            proto = 'ICMP'
            info  = f'type={pkt[ICMP].type}'

        # ── Record packet for UI ──────────────────────────
        packet_rec = {
            'time':    now.isoformat(),
            'src':     f"{src_ip}:{sport}",
            'dst':     f"{dst_ip}:{dport}",
            'src_ip':  src_ip,
            'dst_ip':  dst_ip,
            'proto':   proto,
            'length':  pkt_len,
            'flags':   flags,
            'info':    info,
            'direction': 'IN' if dst_ip == self._local_ip else 'OUT',
        }
        with self._lock:
            self._packets.append(packet_rec)
            if len(self._packets) > 2000:
                self._packets = self._packets[-2000:]

        # ── Run detection on accumulated events ───────────
        self._run_detection(now)

    # ─────────────────────────────────────────────────────
    # psutil poll loop — runs even without scapy
    # ─────────────────────────────────────────────────────

    def _psutil_loop(self):
        last_io      = None
        last_io_time = None

        while True:
            try:
                now = datetime.utcnow()

                # ── Connections ─────────────────────────────
                conns      = []
                proc_cache = {}
                try:
                    raw_conns = psutil.net_connections(kind='inet')
                except Exception:
                    raw_conns = []

                for c in raw_conns:
                    if not c.laddr or not c.raddr:
                        continue
                    rip   = c.raddr.ip
                    rport = c.raddr.port
                    lport = c.laddr.port
                    pid   = c.pid or 0

                    if pid not in proc_cache:
                        proc_cache[pid] = _get_proc_name(pid)

                    conn_info = {
                        'timestamp':   now.isoformat(),
                        'local':       f"{c.laddr.ip}:{lport}",
                        'remote':      f"{rip}:{rport}",
                        'status':      c.status,
                        'pid':         pid,
                        'process':     proc_cache[pid],
                        'local_port':  lport,
                        'remote_ip':   rip,
                        'remote_port': rport,
                        'direction':   'IN' if lport < 1024 else 'OUT',
                    }
                    conns.append(conn_info)

                    # Feed scan events from psutil (when no scapy)
                    if self.capture_mode == 'psutil':
                        with self._lock:
                            self._scan_events[rip].append((now, lport))
                            if rport in AUTH_PORTS:
                                self._brute_events[rip].append((now, rport))

                with self._lock:
                    self._connections = conns
                    self._stats['total_connections'] = len(conns)

                # ── Exfil detection ─────────────────────────
                try:
                    io = psutil.net_io_counters()
                    with self._lock:
                        self._stats['bytes_sent_total'] = io.bytes_sent

                    if last_io is not None:
                        elapsed = (now - last_io_time).total_seconds()
                        delta   = io.bytes_sent - last_io.bytes_sent
                        if elapsed > 0 and delta > EXFIL_BYTES_THRESHOLD:
                            mb = round(delta / (1024 * 1024), 1)
                            self._raise_alert(
                                alert_type='DATA_EXFIL', ip=self._local_ip,
                                severity='CRITICAL',
                                description=f"Data exfiltration: {mb} MB outbound in {elapsed:.0f}s",
                                extra={'bytes_sent': delta, 'elapsed_sec': round(elapsed, 1)},
                                now=now,
                            )
                    last_io      = io
                    last_io_time = now
                except Exception:
                    pass

                # ── Detection pass ──────────────────────────
                self._run_detection(now)

                # ── Emit live stats to all clients ──────────
                self._emit_live_update(now, conns)

            except Exception as e:
                print(f"⚠️  psutil loop error: {e}")

            time.sleep(POLL_INTERVAL)

    # ─────────────────────────────────────────────────────
    # Detection — called after events are accumulated
    # ─────────────────────────────────────────────────────

    def _run_detection(self, now: datetime):
        scan_cutoff  = now - timedelta(seconds=SCAN_WINDOW_SECONDS)
        brute_cutoff = now - timedelta(seconds=BRUTE_WINDOW_SECONDS)

        with self._lock:
            # Expire old scan events
            for ip in list(self._scan_events):
                self._scan_events[ip] = [(t, p) for t, p in self._scan_events[ip] if t > scan_cutoff]
                if not self._scan_events[ip]:
                    del self._scan_events[ip]

            # Expire old brute events
            for ip in list(self._brute_events):
                self._brute_events[ip] = [(t, p) for t, p in self._brute_events[ip] if t > brute_cutoff]
                if not self._brute_events[ip]:
                    del self._brute_events[ip]

            # Expire old SYN events
            for ip in list(self._syn_events):
                self._syn_events[ip] = [t for t in self._syn_events[ip] if t > scan_cutoff]
                if not self._syn_events[ip]:
                    del self._syn_events[ip]

            scan_snap  = {ip: list(evs) for ip, evs in self._scan_events.items()}
            brute_snap = {ip: list(evs) for ip, evs in self._brute_events.items()}
            syn_snap   = {ip: list(ts)  for ip, ts  in self._syn_events.items()}

        # Port scan detection
        for src_ip, events in scan_snap.items():
            distinct_ports = {p for _, p in events}
            if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
                self._raise_alert(
                    alert_type='PORT_SCAN', ip=src_ip, severity='HIGH',
                    description=(
                        f"Port scan from {src_ip} → {self._local_ip}: "
                        f"{len(distinct_ports)} ports in {SCAN_WINDOW_SECONDS}s"
                    ),
                    extra={
                        'ports_hit': sorted(distinct_ports)[:40],
                        'port_count': len(distinct_ports),
                        'target_ip': self._local_ip,
                        'proto': 'TCP',
                    },
                    now=now,
                )

        # Brute force detection
        brute_counts: dict = defaultdict(lambda: defaultdict(int))
        for src_ip, events in brute_snap.items():
            for _, dport in events:
                brute_counts[src_ip][dport] += 1

        for src_ip, port_counts in brute_counts.items():
            for dport, count in port_counts.items():
                if count >= BRUTE_FORCE_THRESHOLD:
                    service = {22: 'SSH', 3389: 'RDP', 21: 'FTP', 23: 'Telnet',
                               445: 'SMB', 5900: 'VNC', 25: 'SMTP', 110: 'POP3'}.get(dport, f'port {dport}')
                    self._raise_alert(
                        alert_type='BRUTE_FORCE', ip=src_ip, severity='HIGH',
                        description=(
                            f"Brute force {service} from {src_ip}: "
                            f"{count} attempts in {BRUTE_WINDOW_SECONDS}s"
                        ),
                        extra={
                            'target_port':      dport,
                            'service':          service,
                            'connection_count': count,
                            'target_ip':        self._local_ip,
                            'proto':            'TCP',
                        },
                        now=now,
                    )

        # SYN flood detection
        for src_ip, timestamps in syn_snap.items():
            rate = len(timestamps) / max(SCAN_WINDOW_SECONDS, 1)
            if len(timestamps) >= SYN_FLOOD_THRESHOLD:
                self._raise_alert(
                    alert_type='SYN_FLOOD', ip=src_ip, severity='CRITICAL',
                    description=f"SYN flood from {src_ip}: {len(timestamps)} SYNs in {SCAN_WINDOW_SECONDS}s",
                    extra={'syn_count': len(timestamps), 'rate_per_sec': round(rate, 1)},
                    now=now,
                )

    # ─────────────────────────────────────────────────────
    # Alert dispatch
    # ─────────────────────────────────────────────────────

    def _raise_alert(self, alert_type: str, ip: str, severity: str,
                     description: str, extra: dict, now: datetime):
        dedup_key = (alert_type, ip)
        with self._lock:
            last = self._last_alert.get(dedup_key)
            if last and (now - last).total_seconds() < DEDUP_WINDOW_SECONDS:
                return
            self._last_alert[dedup_key] = now
            self._stats['suspicious_ips'].add(ip)
            self._stats['alerts_today'] += 1
            if alert_type == 'PORT_SCAN':
                self._stats['scans_detected'] += 1
            elif alert_type == 'BRUTE_FORCE':
                self._stats['brute_force_detected'] += 1

        alert = {
            'timestamp':   now.isoformat(),
            'type':        alert_type,
            'ip':          ip,
            'severity':    severity,
            'description': description,
            **extra,
        }

        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 200:
                self._alerts = self._alerts[-200:]

        print(f"🔴 ALERT [{alert_type}] {description}")

        # 1 — SOC socket
        try:
            self.socketio.emit('network_alert', alert)
        except Exception as e:
            print(f"⚠️  socket emit failed: {e}")

        # 2 — Audit log
        try:
            from utils.db import log_network_audit
            log_network_audit(
                event_type=alert_type, ip=ip, severity=severity,
                description=description,
                protocol=extra.get('proto', ''),
                port=extra.get('target_port') or extra.get('dst_port'),
                details=str(extra),
            )
        except Exception as e:
            print(f"⚠️  audit log failed: {e}")

        # 3 — Full incident + geolocation + live_incident emit
        try:
            self._build_and_emit_incident(alert_type, ip, severity, description, extra, now)
        except Exception as e:
            print(f"⚠️  incident build failed: {e}")

    def _build_and_emit_incident(self, alert_type, ip, severity, description, extra, now):
        """Build full incident with geo, risk score, emit live_incident to SOC."""
        import threading as _threading

        def _work():
            try:
                from utils.geo_lookup import geolocate, format_geo_display, is_private_ip
                from utils.risk_scorer import calculate_risk
                from utils.incident_manager import create_incident

                geo_raw     = geolocate(ip)
                geo_display = format_geo_display(geo_raw)

                # Risk score — factor in what we know
                SEVERITY_NETWORK_MAP = {
                    'CRITICAL': 0.95, 'HIGH': 0.80, 'MEDIUM': 0.55, 'LOW': 0.30
                }

                # Try ML prediction first
                ml_result = None
                try:
                    from models.network_scorer import predict_attack_type, is_loaded
                    if is_loaded():
                        ml_result = predict_attack_type(alert_type, extra)
                except Exception:
                    pass

                # Attack-type specific boosts
                extra_signals = {}
                if alert_type == 'BRUTE_FORCE':
                    extra_signals = {
                        'process_suspicious': True,
                        'process_risk': severity,
                    }
                elif alert_type in ('PORT_SCAN', 'NULL_SCAN', 'XMAS_SCAN', 'FIN_SCAN'):
                    extra_signals = {}
                elif alert_type == 'SYN_FLOOD':
                    extra_signals = {'process_suspicious': True, 'process_risk': 'CRITICAL'}
                elif alert_type == 'DATA_EXFIL':
                    extra_signals = {
                        'ml_prediction': 'Ransomware',
                        'ml_confidence': 70.0,
                        'file_events': 10,
                    }

                # Use ML risk score if available, else rule-based
                if ml_result and ml_result.get('model') != 'not_loaded':
                    ml_risk_score = ml_result.get('risk_score', 0)
                    ml_confidence = ml_result.get('confidence', 0)
                    ml_prediction = ml_result.get('prediction', '')
                    extra_signals['ml_prediction']  = ml_prediction if ml_prediction != 'BENIGN' else None
                    extra_signals['ml_confidence']  = ml_confidence
                    extra_signals['ml_score']       = ml_risk_score

                rs = calculate_risk(
                    network_alert=alert_type,
                    network_severity=severity,
                    correlated_signals=3,
                    **extra_signals,
                )

                MITRE = {
                    'PORT_SCAN':   ('T1046', 'Network Service Discovery'),
                    'BRUTE_FORCE': ('T1110', 'Brute Force'),
                    'C2_BEACON':   ('T1071', 'Application Layer Protocol'),
                    'DATA_EXFIL':  ('T1041', 'Exfiltration Over C2 Channel'),
                    'SYN_FLOOD':   ('T1498', 'Network Denial of Service'),
                    'NULL_SCAN':   ('T1046', 'Network Service Discovery'),
                    'XMAS_SCAN':   ('T1046', 'Network Service Discovery'),
                    'FIN_SCAN':    ('T1046', 'Network Service Discovery'),
                }
                mitre_id, mitre_name = MITRE.get(alert_type, ('T1046', 'Network Activity'))

                dest_port = extra.get('target_port') or extra.get('dst_port') or 0
                proto     = extra.get('proto', 'TCP')

                # MAC: only observable on same LAN
                is_local = _is_private(ip) or ip == '127.0.0.1'
                mac_note  = 'Unknown (LAN — ARP lookup needed)' if is_local else 'Not observable remotely'

                incident = create_incident(
                    attack_type=alert_type,
                    title=f'{alert_type.replace("_"," ")} from {ip}',
                    severity=severity,
                    source_ip=ip,
                    dest_ip=self._local_ip,
                    dest_port=dest_port,
                    protocol=proto,
                    geo_info=geo_display,
                    initial_events=[{
                        'time':        now.isoformat(),
                        'event':       f'{alert_type} detected',
                        'description': description,
                        'severity':    severity,
                    }],
                )

                payload = {
                    'incident_id': incident.get('id'),
                    'attack_type': alert_type,
                    'title':       incident.get('title'),
                    'severity':    severity,
                    'risk_score':  rs.final_score,
                    'risk_level':  rs.risk_level,
                    'description': description,
                    'timestamp':   now.isoformat(),

                    'attacker': {
                        'ip':       ip,
                        'port':     extra.get('source_port'),
                        'protocol': proto,
                        'mac':      mac_note,
                        'geo':      geo_display,
                    },
                    'target': {
                        'ip':   self._local_ip,
                        'port': dest_port,
                    },
                    'network': {
                        'ports_hit':        extra.get('ports_hit', []),
                        'port_count':       extra.get('port_count', 0),
                        'connection_count': extra.get('connection_count', 0),
                        'service':          extra.get('service', ''),
                        'bytes_sent':       extra.get('bytes_sent', 0),
                        'target_port':      dest_port,
                        'protocol':         proto,
                        'capture_mode':     self.capture_mode,
                    },
                    'mitre': {
                        'id':   mitre_id,
                        'name': mitre_name,
                        'url':  f'https://attack.mitre.org/techniques/{mitre_id}/',
                    },
                    'ml': {
                        'prediction':    ml_result.get('prediction')  if ml_result else None,
                        'confidence':    ml_result.get('confidence')  if ml_result else None,
                        'is_anomaly':    ml_result.get('is_anomaly')  if ml_result else None,
                        'anomaly_score': ml_result.get('anomaly_score') if ml_result else None,
                        'risk_score':    ml_result.get('risk_score')  if ml_result else None,
                        'model':         ml_result.get('model')       if ml_result else 'not_loaded',
                        'loaded':        ml_result is not None and ml_result.get('model') != 'not_loaded',
                    },
                    'risk_factors': rs.to_dict().get('factors', []),
                    'status': {
                        'detected':   True,
                        'honeypot':   False,
                        'ml':         ml_result is not None and ml_result.get('model') != 'not_loaded',
                        'quarantine': False,
                        'evidence':   False,
                        'blockchain': False,
                    },
                }

                self.socketio.emit('live_incident', payload)
                self.socketio.emit('high_threat_alert', {
                    'prediction':   alert_type,
                    'threat_score': rs.final_score,
                    'risk_level':   severity,
                    'timestamp':    now.isoformat(),
                    'source_ip':    ip,
                    'event_type':   alert_type,
                })
                print(f"🚨 live_incident → {alert_type} from {ip} | risk={rs.final_score}/100 | geo={geo_display.get('display','?')}")

            except Exception as e:
                print(f"⚠️  _build_and_emit_incident failed: {e}")

        _threading.Thread(target=_work, daemon=True).start()

    # ─────────────────────────────────────────────────────
    # Live stats emit
    # ─────────────────────────────────────────────────────

    def _emit_live_update(self, now, conns):
        try:
            with self._lock:
                stats = {
                    'total_connections':    self._stats['total_connections'],
                    'suspicious_ips':       len(self._stats['suspicious_ips']),
                    'alerts_today':         self._stats['alerts_today'],
                    'bytes_sent_mb':        round(self._stats['bytes_sent_total'] / (1024 * 1024), 2),
                    'packets_captured':     self._stats['packets_captured'],
                    'scans_detected':       self._stats['scans_detected'],
                    'brute_force_detected': self._stats['brute_force_detected'],
                    'capture_mode':         self.capture_mode,
                    'local_ip':             self._local_ip,
                }
                pkts = list(self._packets[-50:])

            self.socketio.emit('network_update', {
                'timestamp':   now.isoformat(),
                'stats':       stats,
                'connections': conns[:100],
                'packets':     pkts,
            })
        except Exception as e:
            print(f"⚠️  network_update emit failed: {e}")


# ─────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────

def _get_proc_name(pid: int) -> str:
    if not pid:
        return 'unknown'
    try:
        return psutil.Process(pid).name()
    except Exception:
        return 'unknown'


# Singleton
_monitor_instance = None

def get_monitor():
    return _monitor_instance

def set_monitor(m):
    global _monitor_instance
    _monitor_instance = m

"""
Flow Feature Extraction
Converts raw packets into CICFlowMeter-compatible features for ML models
"""
import threading
import time
import math
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def _to_number(value, default=0):
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _tcp_flag_mask(value):
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        flags = str(value).upper()
        return sum(
            bit for name, bit in (
                ('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04), ('PSH', 0x08),
                ('ACK', 0x10), ('URG', 0x20), ('ECE', 0x40), ('CWR', 0x80),
            )
            if name in flags
        )


class Flow:
    """Represents a network flow (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)"""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Flow state
        self.first_seen: datetime = datetime.utcnow()
        self.last_seen: datetime = self.first_seen
        self.packets: List[Dict] = []
        self.forward_packets: List[Dict] = []
        self.backward_packets: List[Dict] = []
        
        # Byte counters
        self.total_bytes = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        
        # Packet counters
        self.total_packets = 0
        self.forward_packets_count = 0
        self.backward_packets_count = 0
        
        # IAT (Inter-Arrival Time) tracking
        self.iat_list: List[float] = []
        self.fwd_iat_list: List[float] = []
        self.bwd_iat_list: List[float] = []
        self.last_packet_time: Optional[float] = None
        self.first_packet_time: Optional[float] = None
        
        # TCP flags
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.ece_count = 0
        self.cwr_count = 0
        self.fwd_psh_count = 0
        self.bwd_psh_count = 0
        self.fwd_urg_count = 0
        self.bwd_urg_count = 0
        self.forward_header_length = 0
        self.backward_header_length = 0
        self.initial_window_sizes = {}
        self.forward_data_packets = 0
        self.min_forward_segment_size = None
        
        # Packet lengths
        self.packet_lengths: List[int] = []
        self.fwd_packet_lengths: List[int] = []
        self.bwd_packet_lengths: List[int] = []
        
        # Active/Idle tracking
        self.active_periods: List[float] = []
        self.idle_periods: List[float] = []
        
    def add_packet(self, packet: Dict):
        """Add a packet to the flow"""
        now = datetime.utcnow()
        self.last_seen = now
        self.packets.append(packet)
        self.total_packets += 1
        
        # Extract packet info
        packet_len = _to_number(packet.get('ip.len'))
        if not packet_len and packet.get('ipv6.plen') is not None:
            packet_len = _to_number(packet.get('ipv6.plen')) + 40
        if not packet_len:
            packet_len = _to_number(packet.get('frame.len'))
        packet_len = int(packet_len)
        src_ip = packet.get('ip.src') or packet.get('ipv6.src')
        flags = _tcp_flag_mask(packet.get('tcp.flags', ''))
        tcp_header_length = int(_to_number(packet.get('tcp.hdr_len')))
        ip_header_length = int(_to_number(packet.get('ip.hdr_len')))
        if not ip_header_length and packet.get('ipv6.src'):
            ip_header_length = 40
        header_length = tcp_header_length + ip_header_length

        # Determine direction
        is_forward = (src_ip == self.src_ip)
        
        if is_forward:
            self.forward_packets.append(packet)
            self.forward_packets_count += 1
            self.forward_bytes += packet_len
            self.fwd_packet_lengths.append(packet_len)
            self.forward_header_length += header_length
            if packet.get('tcp.window_size_value') is not None:
                self.initial_window_sizes.setdefault(
                    'forward', int(_to_number(packet.get('tcp.window_size_value')))
                )
            if packet_len:
                self.min_forward_segment_size = (
                    packet_len if self.min_forward_segment_size is None
                    else min(self.min_forward_segment_size, packet_len)
                )
            if _to_number(packet.get('tcp.len')) > 0:
                self.forward_data_packets += 1
        else:
            self.backward_packets.append(packet)
            self.backward_packets_count += 1
            self.backward_bytes += packet_len
            self.bwd_packet_lengths.append(packet_len)
            self.backward_header_length += header_length
            if packet.get('tcp.window_size_value') is not None:
                self.initial_window_sizes.setdefault(
                    'backward', int(_to_number(packet.get('tcp.window_size_value')))
                )
        
        self.total_bytes += packet_len
        self.packet_lengths.append(packet_len)
        
        # TCP flags
        if flags & 0x02:
            self.syn_count += 1
        if flags & 0x10:
            self.ack_count += 1
        if flags & 0x04:
            self.rst_count += 1
        if flags & 0x01:
            self.fin_count += 1
        if flags & 0x08:
            self.psh_count += 1
            if is_forward:
                self.fwd_psh_count += 1
            else:
                self.bwd_psh_count += 1
        if flags & 0x20:
            if is_forward:
                self.fwd_urg_count += 1
            else:
                self.bwd_urg_count += 1
        if flags & 0x40:
            self.ece_count += 1
        if flags & 0x80:
            self.cwr_count += 1
        
        # IAT calculation
        timestamp = _to_number(packet.get('frame.time_epoch'), None)
        if timestamp is not None:
            if self.first_packet_time is None:
                self.first_packet_time = timestamp
            if self.last_packet_time is not None:
                iat = max(0.0, timestamp - self.last_packet_time)
                self.iat_list.append(iat)
                if is_forward:
                    self.fwd_iat_list.append(iat)
                else:
                    self.bwd_iat_list.append(iat)
                if iat > 1.0:
                    self.idle_periods.append(iat)
                else:
                    self.active_periods.append(iat)
            self.last_packet_time = timestamp

    def is_expired(self, timeout_seconds: int = 300) -> bool:
        """Check if flow is expired (no packets for timeout_seconds)"""
        return (datetime.utcnow() - self.last_seen).total_seconds() > timeout_seconds

    def get_features(self) -> Dict:
        """
        Extract the feature schema consumed by the trained CICFlowMeter model.
        Timing features use microseconds; rates use seconds.
        """
        duration_seconds = (
            max(0.0, self.last_packet_time - self.first_packet_time)
            if self.first_packet_time is not None and self.last_packet_time is not None
            else (self.last_seen - self.first_seen).total_seconds()
        )
        if duration_seconds == 0:
            duration_seconds = 0.000001
        duration = duration_seconds * 1_000_000
        
        # Calculate statistics
        def calc_stats(values):
            if not values:
                return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
            mean = sum(values) / len(values)
            return {
                'mean': mean,
                'std': (sum((x - mean) ** 2 for x in values) / len(values)) ** 0.5 if len(values) > 1 else 0,
                'min': min(values),
                'max': max(values)
            }
        
        # Packet length stats
        pkt_len_stats = calc_stats(self.packet_lengths)
        fwd_pkt_len_stats = calc_stats(self.fwd_packet_lengths)
        bwd_pkt_len_stats = calc_stats(self.bwd_packet_lengths)
        
        # IAT stats
        iat_stats = calc_stats(self.iat_list)
        fwd_iat_stats = calc_stats(self.fwd_iat_list)
        bwd_iat_stats = calc_stats(self.bwd_iat_list)
        
        # Active/Idle stats
        active_stats = calc_stats(self.active_periods) if self.active_periods else {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
        idle_stats = calc_stats(self.idle_periods) if self.idle_periods else {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
        
        # Build feature vector (46 features matching network_model_info.json)
        features = {
            'Flow Duration': duration,
            'Total Fwd Packets': self.forward_packets_count,
            'Total Backward Packets': self.backward_packets_count,
            'Total Length of Fwd Packets': self.forward_bytes,
            'Total Length of Bwd Packets': self.backward_bytes,
            'Fwd Packet Length Max': fwd_pkt_len_stats['max'],
            'Fwd Packet Length Min': fwd_pkt_len_stats['min'],
            'Fwd Packet Length Mean': fwd_pkt_len_stats['mean'],
            'Fwd Packet Length Std': fwd_pkt_len_stats['std'],
            'Bwd Packet Length Max': bwd_pkt_len_stats['max'],
            'Bwd Packet Length Min': bwd_pkt_len_stats['min'],
            'Bwd Packet Length Mean': bwd_pkt_len_stats['mean'],
            'Bwd Packet Length Std': bwd_pkt_len_stats['std'],
            'Flow Bytes/s': self.total_bytes / duration_seconds,
            'Flow Packets/s': self.total_packets / duration_seconds,
            'Flow IAT Mean': iat_stats['mean'] * 1_000_000,
            'Flow IAT Std': iat_stats['std'] * 1_000_000,
            'Flow IAT Max': iat_stats['max'] * 1_000_000,
            'Flow IAT Min': iat_stats['min'] * 1_000_000,
            'Fwd IAT Total': sum(self.fwd_iat_list) * 1_000_000,
            'Fwd IAT Mean': fwd_iat_stats['mean'] * 1_000_000,
            'Fwd IAT Std': fwd_iat_stats['std'] * 1_000_000,
            'Fwd IAT Max': fwd_iat_stats['max'] * 1_000_000,
            'Fwd IAT Min': fwd_iat_stats['min'] * 1_000_000,
            'Bwd IAT Total': sum(self.bwd_iat_list) * 1_000_000,
            'Bwd IAT Mean': bwd_iat_stats['mean'] * 1_000_000,
            'Bwd IAT Std': bwd_iat_stats['std'] * 1_000_000,
            'Bwd IAT Max': bwd_iat_stats['max'] * 1_000_000,
            'Bwd IAT Min': bwd_iat_stats['min'] * 1_000_000,
            'Fwd PSH Flags': self.fwd_psh_count,
            'Bwd PSH Flags': self.bwd_psh_count,
            'Fwd URG Flags': self.fwd_urg_count,
            'Bwd URG Flags': self.bwd_urg_count,
            'Fwd Header Length': self.forward_header_length,
            'Bwd Header Length': self.backward_header_length,
            'Fwd Packets/s': self.forward_packets_count / duration_seconds,
            'Bwd Packets/s': self.backward_packets_count / duration_seconds,
            'Min Packet Length': pkt_len_stats['min'],
            'Max Packet Length': pkt_len_stats['max'],
            'Packet Length Mean': pkt_len_stats['mean'],
            'Packet Length Std': pkt_len_stats['std'],
            'Packet Length Variance': pkt_len_stats['std'] ** 2,
            'FIN Flag Count': self.fin_count,
            'SYN Flag Count': self.syn_count,
            'RST Flag Count': self.rst_count,
            'PSH Flag Count': self.psh_count,
            'ACK Flag Count': self.ack_count,
            'URG Flag Count': self.fwd_urg_count + self.bwd_urg_count,
            'Down/Up Ratio': self.backward_bytes / self.forward_bytes if self.forward_bytes > 0 else 0,
            'Average Packet Size': self.total_bytes / self.total_packets if self.total_packets > 0 else 0,
            'Avg Fwd Segment Size': self.forward_bytes / self.forward_packets_count if self.forward_packets_count > 0 else 0,
            'Avg Bwd Segment Size': self.backward_bytes / self.backward_packets_count if self.backward_packets_count > 0 else 0,
            'Fwd Header Length.1': self.forward_header_length,
            'Fwd Avg Bytes/Bulk': 0,  # Not calculated
            'Fwd Avg Packets/Bulk': 0,  # Not calculated
            'Fwd Avg Bulk Rate': 0,  # Not calculated
            'Bwd Avg Bytes/Bulk': 0,  # Not calculated
            'Bwd Avg Packets/Bulk': 0,  # Not calculated
            'Bwd Avg Bulk Rate': 0,  # Not calculated
            'Subflow Fwd Packets': self.forward_packets_count,
            'Subflow Fwd Bytes': self.forward_bytes,
            'Subflow Bwd Packets': self.backward_packets_count,
            'Subflow Bwd Bytes': self.backward_bytes,
            'Init_Win_bytes_forward': self.initial_window_sizes.get('forward', 0),
            'Init_Win_bytes_backward': self.initial_window_sizes.get('backward', 0),
            'act_data_pkt_fwd': self.forward_data_packets,
            'act_data_pkt_bwd': self.backward_packets_count,
            'CWE Flag Count': self.cwr_count,
            'ECE Flag Count': self.ece_count,
            'min_seg_size_forward': self.min_forward_segment_size or 0,
            'Active Mean': active_stats['mean'] * 1_000_000,
            'Active Std': active_stats['std'] * 1_000_000,
            'Active Max': active_stats['max'] * 1_000_000,
            'Active Min': active_stats['min'] * 1_000_000,
            'Idle Mean': idle_stats['mean'] * 1_000_000,
            'Idle Std': idle_stats['std'] * 1_000_000,
            'Idle Max': idle_stats['max'] * 1_000_000,
            'Idle Min': idle_stats['min'] * 1_000_000,
        }
        
        return features


class FlowExtractor:
    """Manages flow extraction from packets"""
    
    def __init__(self, flow_timeout: int = 30, min_packets: int = 10):
        self.flows: Dict[str, Flow] = {}
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets  # Emit flow after this many packets
        self._lock = threading.Lock()
        self.flow_callback: Optional[callable] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        
    def start(self, callback: callable):
        """Start flow extraction with callback for completed flows"""
        self.flow_callback = callback
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info("Flow extractor started")
        
    def stop(self):
        """Stop flow extraction"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        logger.info("Flow extractor stopped")
        
    def _cleanup_loop(self):
        """Periodically clean up expired flows"""
        while self._running:
            time.sleep(10)  # Check every 10 seconds
            with self._lock:
                expired_flows = [
                    (key, flow) for key, flow in self.flows.items()
                    if flow.is_expired(self.flow_timeout)
                ]
                for key, _ in expired_flows:
                    del self.flows[key]

            for _, flow in expired_flows:
                if self.flow_callback and flow.total_packets >= self.min_packets:
                    try:
                        features = flow.get_features()
                        self.flow_callback(features, flow)
                    except Exception as e:
                        logger.error(f"Error in flow callback: {e}")

            if expired_flows:
                logger.info(f"Cleaned up {len(expired_flows)} expired flows")
    
    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Generate flow key (5-tuple)"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
    
    def add_packet(self, packet: Dict):
        """Add packet to appropriate flow"""
        src_ip = packet.get('ip.src') or packet.get('ipv6.src')
        dst_ip = packet.get('ip.dst') or packet.get('ipv6.dst')
        
        if not src_ip or not dst_ip:
            return
        
        # Get ports (TCP or UDP)
        src_port = packet.get('tcp.srcport') or packet.get('udp.srcport') or 0
        dst_port = packet.get('tcp.dstport') or packet.get('udp.dstport') or 0
        
        # Determine protocol
        ip_proto = int(_to_number(
            packet.get('ip.proto') or packet.get('ipv6.nxt'),
            -1,
        ))
        if ip_proto == 6:
            protocol = 'TCP'
        elif ip_proto == 17:
            protocol = 'UDP'
        elif ip_proto == 1:
            protocol = 'ICMP'
        else:
            protocol = 'OTHER'
        
        # Create bidirectional flow key
        # Ensure consistent ordering (lower IP first)
        if src_ip < dst_ip:
            key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            key = self._get_flow_key(dst_ip, src_ip, dst_port, src_port, protocol)
        
        flow_to_emit = None
        callback = None
        with self._lock:
            if key not in self.flows:
                self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
            
            flow = self.flows[key]
            flow.add_packet(packet)
            
            # Emit flow if it has enough packets (for real-time detection)
            # Emit every 10 packets after the first 10
            if flow.total_packets >= self.min_packets and flow.total_packets % self.min_packets == 0:
                flow_to_emit = flow
                callback = self.flow_callback

        if flow_to_emit and callback:
            try:
                features = flow_to_emit.get_features()
                callback(features, flow_to_emit)
            except Exception as e:
                logger.error(f"Error in flow callback: {e}")
    
    def get_active_flows(self) -> List[Dict]:
        """Get all active flows"""
        with self._lock:
            return [
                {
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol,
                    'packets': flow.total_packets,
                    'bytes': flow.total_bytes,
                    'duration': (flow.last_seen - flow.first_seen).total_seconds(),
                    'first_seen': flow.first_seen.isoformat(),
                    'last_seen': flow.last_seen.isoformat(),
                }
                for flow in self.flows.values()
            ]
    
    def get_flow_count(self) -> int:
        """Get number of active flows"""
        with self._lock:
            return len(self.flows)


# Global flow extractor instance
_flow_extractor: Optional[FlowExtractor] = None


def get_flow_extractor() -> FlowExtractor:
    """Get or create global flow extractor"""
    global _flow_extractor
    if _flow_extractor is None:
        _flow_extractor = FlowExtractor()
    return _flow_extractor


def set_flow_extractor(extractor: FlowExtractor):
    """Set global flow extractor (for testing)"""
    global _flow_extractor
    _flow_extractor = extractor

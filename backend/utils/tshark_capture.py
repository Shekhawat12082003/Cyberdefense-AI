"""
TShark/Dumpcap Capture Service
Real-time network packet capture using Wireshark command-line tools
"""
import subprocess
import threading
import json
import time
import re
import logging
import sys
from datetime import datetime
from typing import Optional, List, Dict, Callable
from pathlib import Path

logger = logging.getLogger(__name__)

# Detect TShark path
if sys.platform == 'win32':
    # Windows: Check common installation paths
    tshark_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    TSHARK_PATH = None
    for path in tshark_paths:
        if Path(path).exists():
            TSHARK_PATH = path
            break
    if not TSHARK_PATH:
        TSHARK_PATH = "tshark"  # Fallback to PATH
else:
    TSHARK_PATH = "tshark"  # Linux/macOS


class TSharkCapture:
    """Manages live packet capture using TShark/Dumpcap"""

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.capture_process: Optional[subprocess.Popen] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.stderr_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        self.selected_interface: Optional[str] = None
        self.packet_callback: Optional[Callable] = None
        self.packets_captured = 0
        self.start_time: Optional[datetime] = None
        self.local_ip: Optional[str] = None
        self.local_ips = set()
        self._lock = threading.Lock()

    def get_interfaces(self) -> List[Dict[str, str]]:
        """
        Get available network interfaces using TShark
        Returns list of interface info dictionaries
        """
        try:
            result = subprocess.run(
                [TSHARK_PATH, '-D'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    # Parse TShark interface output
                    # Format: "1. \Device\NPF_{GUID} (Adapter Name)"
                    match = re.match(r'(\d+)\.\s+([^\(]+)\s*\(([^)]+)\)', line)
                    if match:
                        idx, device, name = match.groups()
                        interfaces.append({
                            'id': idx,
                            'device': device.strip(),
                            'name': name.strip(),
                            'display': f"{name.strip()} ({device.strip()})"
                        })
                    else:
                        # Fallback parsing
                        interfaces.append({
                            'id': str(len(interfaces) + 1),
                            'device': line.strip(),
                            'name': line.strip(),
                            'display': line.strip()
                        })
            
            logger.info(f"Found {len(interfaces)} network interfaces")
            return interfaces
            
        except FileNotFoundError:
            logger.error(f"TShark not found at: {TSHARK_PATH}")
            logger.error("Please ensure Wireshark is installed and TShark is accessible")
            logger.error("Windows: TShark should be at C:\\Program Files\\Wireshark\\tshark.exe")
            return []
        except subprocess.TimeoutExpired:
            logger.error("TShark interface detection timed out")
            return []
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []

    def start_capture(self, interface: str, callback: Callable, filter_expr: str = "") -> bool:
        """
        Start live packet capture on specified interface
        
        Args:
            interface: Network interface name/device
            callback: Function to call for each packet
            filter_expr: Optional BPF filter expression
            
        Returns:
            True if capture started successfully
        """
        with self._lock:
            if self.is_capturing:
                logger.warning("Capture already in progress")
                return False
            
            self.selected_interface = interface
            self.packet_callback = callback
            self.is_capturing = True
            self.packets_captured = 0
            self.start_time = datetime.utcnow()
            
            # Start capture thread
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                args=(interface, filter_expr),
                daemon=True
            )
            self.capture_thread.start()
            
            logger.info(f"Started capture on interface: {interface}")
            return True

    def _capture_loop(self, interface: str, filter_expr: str):
        """Main capture loop running in background thread"""
        try:
            # Build TShark command
            # Use -T fields for simpler tab-separated output
            cmd = [
                TSHARK_PATH,
                '-i', interface,
                '-l',  # Line buffered
                '-T', 'fields',
                '-E', 'header=y',
                '-e', 'frame.time_epoch',
                '-e', 'frame.number',
                '-e', '_ws.col.Protocol',
                '-e', '_ws.col.Info',
                '-e', 'dns.qry.name',
                '-e', 'dns.qry.type',
                '-e', 'tcp.flags',
                '-e', 'quic.long.packet_type',
                '-e', 'tls.record.content_type',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'ipv6.src',
                '-e', 'ipv6.dst',
                '-e', 'ip.ttl',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'ip.proto',
                '-e', 'ipv6.nxt',
                '-e', 'ip.len',
                '-e', 'ipv6.plen',
                '-e', 'ip.hdr_len',
                '-e', 'tcp.hdr_len',
                '-e', 'tcp.window_size_value',
                '-e', 'frame.len',
                '-e', 'tcp.analysis.ack_rtt',
                '-e', 'tcp.len',
                '-e', 'udp.length',
            ]
            
            if filter_expr:
                cmd.extend(['-f', filter_expr])
            
            logger.info(f"Running TShark: {' '.join(cmd)}")
            
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            self.stderr_thread = threading.Thread(
                target=self._drain_stderr,
                args=(self.capture_process.stderr,),
                daemon=True,
            )
            self.stderr_thread.start()
            
            # Process output line by line
            header_parsed = False
            field_names = []
            
            for line in self.capture_process.stdout:
                if not self.is_capturing:
                    break
                    
                if line.strip():
                    try:
                        # TShark fields output: header first, then data
                        if not header_parsed:
                            if line.startswith('frame.time_epoch'):
                                # Parse header
                                field_names = line.strip().split('\t')
                                header_parsed = True
                                continue
                        
                        # Parse data line
                        values = line.strip().split('\t')
                        if len(values) == len(field_names):
                            packet_data = dict(zip(field_names, values))
                            
                            # Convert numeric fields
                            if 'frame.time_epoch' in packet_data:
                                packet_data['frame.time_epoch'] = float(packet_data['frame.time_epoch'])
                            if 'frame.len' in packet_data:
                                packet_data['frame.len'] = int(packet_data['frame.len'])
                            
                            self.packets_captured += 1
                            
                            # Call callback with packet data
                            if self.packet_callback:
                                self.packet_callback(packet_data)
                            
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
            
        except FileNotFoundError:
            logger.error(f"TShark not found at: {TSHARK_PATH}")
            logger.error("Please ensure Wireshark is installed and TShark is accessible")
            self.is_capturing = False
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_capturing = False
        finally:
            self.is_capturing = False
            if self.capture_process:
                self.capture_process.terminate()
                try:
                    self.capture_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.capture_process.kill()
            logger.info("Capture stopped")

    @staticmethod
    def _drain_stderr(stderr):
        """Keep TShark diagnostics visible without allowing its pipe to fill."""
        if stderr is None:
            return
        for line in stderr:
            message = line.strip()
            if message:
                logger.warning("TShark: %s", message)

    def stop_capture(self):
        """Stop the running capture"""
        with self._lock:
            if not self.is_capturing:
                return
            
            self.is_capturing = False
            
            if self.capture_process:
                self.capture_process.terminate()
            
            if self.capture_thread:
                self.capture_thread.join(timeout=5)
            
            duration = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
            logger.info(f"Capture stopped. Packets: {self.packets_captured}, Duration: {duration:.2f}s")

    def get_status(self) -> Dict:
        """Get current capture status"""
        with self._lock:
            duration = 0
            if self.start_time and self.is_capturing:
                duration = (datetime.utcnow() - self.start_time).total_seconds()
            
            return {
                'is_capturing': self.is_capturing,
                'interface': self.selected_interface,
                'packets_captured': self.packets_captured,
                'duration_seconds': duration,
                'packets_per_second': self.packets_captured / duration if duration > 0 else 0
            }


# Global capture instance
_capture_instance: Optional[TSharkCapture] = None


def get_capture() -> TSharkCapture:
    """Get or create global capture instance"""
    global _capture_instance
    if _capture_instance is None:
        _capture_instance = TSharkCapture()
    return _capture_instance


def set_capture(capture: TSharkCapture):
    """Set global capture instance (for testing)"""
    global _capture_instance
    _capture_instance = capture

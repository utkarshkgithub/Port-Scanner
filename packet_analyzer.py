"""
Packet Capture and Inspection Module
Advanced packet analysis using Scapy and PyShark
"""

import time
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import binascii

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available for packet capture")
    # Define dummy classes to prevent NameError
    class IP: pass
    class TCP: pass
    class UDP: pass
    class ICMP: pass
    class HTTPRequest: pass
    class HTTPResponse: pass

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("Warning: PyShark not available for enhanced packet analysis")

@dataclass
class PacketInfo:
    """Data class for packet information"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    ttl: int
    flags: str
    payload_size: int
    payload_preview: str
    headers: Dict[str, Any]

@dataclass
class FlowInfo:
    """Data class for network flow information"""
    flow_id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime]
    packet_count: int
    total_bytes: int
    flags_seen: List[str]
    connection_state: str

class PacketCaptureAnalyzer:
    """Advanced packet capture and analysis tool"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.captured_packets = []
        self.flows = {}
        self.capture_running = False
        self.analysis_callbacks = []
        
        # Protocol analyzers
        self.protocol_analyzers = {
            'HTTP': self._analyze_http,
            'HTTPS': self._analyze_https,
            'SSH': self._analyze_ssh,
            'FTP': self._analyze_ftp,
            'DNS': self._analyze_dns,
            'SMTP': self._analyze_smtp
        }
    
    def _default_config(self) -> Dict:
        """Default configuration for packet capture"""
        return {
            'capture_filter': 'tcp or udp',
            'max_packets': 10000,
            'capture_timeout': 300,  # 5 minutes
            'interface': None,  # Will auto-detect
            'save_pcap': True,
            'pcap_filename': None,
            'deep_packet_inspection': True,
            'flow_timeout': 300,  # 5 minutes
            'payload_analysis': True
        }
    
    def add_analysis_callback(self, callback):
        """Add callback for real-time packet analysis"""
        self.analysis_callbacks.append(callback)
    
    def start_capture(self, duration: int = None, packet_count: int = None) -> str:
        """Start packet capture session"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")
        
        self.capture_running = True
        capture_filter = self.config['capture_filter']
        interface = self.config['interface']
        
        # Auto-detect interface if not specified
        if interface is None:
            try:
                import subprocess
                # Get list of UP interfaces
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                up_interfaces = []
                for line in result.stdout.split('\n'):
                    if 'state UP' in line and '<' in line:
                        # Extract interface name
                        iface_name = line.split(':')[1].strip()
                        if iface_name != 'lo' and not iface_name.startswith('docker') and not iface_name.startswith('br-'):
                            up_interfaces.append(iface_name)
                
                if up_interfaces:
                    interface = up_interfaces[0]  # Use first UP interface
                else:
                    interface = 'lo'  # Fallback to loopback
            except:
                # Fallback to Scapy method
                try:
                    from scapy.arch import get_if_list
                    interfaces = get_if_list()
                    # Prefer non-loopback interfaces
                    for iface in interfaces:
                        if iface != 'lo' and not iface.startswith('docker'):
                            interface = iface
                            break
                    else:
                        interface = 'lo'
                except:
                    interface = 'lo'  # Safe fallback
        
        # Generate filename if not provided
        if self.config['save_pcap'] and not self.config['pcap_filename']:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.config['pcap_filename'] = f"capture_{timestamp}.pcap"
        
        print(f"🔍 Starting packet capture on {interface}")
        print(f"Filter: {capture_filter}")
        if duration:
            print(f"Duration: {duration} seconds")
        if packet_count:
            print(f"Max packets: {packet_count}")
        
        try:
            packets = sniff(
                iface=interface,
                filter=capture_filter,
                timeout=duration or self.config['capture_timeout'],
                count=packet_count or self.config['max_packets'],
                prn=self._process_packet
            )
            
            # Save to pcap file if configured
            if self.config['save_pcap']:
                wrpcap(self.config['pcap_filename'], packets)
                print(f"💾 Packets saved to {self.config['pcap_filename']}")
            
            self.capture_running = False
            return self.config['pcap_filename'] or "capture_complete"
            
        except Exception as e:
            self.capture_running = False
            raise RuntimeError(f"Packet capture failed: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet in real-time"""
        if not self.capture_running:
            return
        
        packet_info = self._extract_packet_info(packet)
        if packet_info:
            self.captured_packets.append(packet_info)
            self._update_flows(packet_info)
            
            # Call analysis callbacks
            for callback in self.analysis_callbacks:
                callback(packet_info)
            
            # Deep packet inspection if enabled
            if self.config['deep_packet_inspection']:
                self._deep_inspect_packet(packet, packet_info)
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from packet"""
        try:
            if not SCAPY_AVAILABLE:
                return None
                
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            timestamp = datetime.now()
            
            # Basic IP information
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            ttl = ip_layer.ttl
            packet_size = len(packet)
            
            # Initialize default values
            source_port = dest_port = 0
            protocol = ip_layer.proto
            flags = ""
            payload_size = 0
            payload_preview = ""
            headers = {"ip": self._extract_ip_headers(ip_layer)}
            
            # TCP specific information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                protocol = "TCP"
                flags = self._extract_tcp_flags(tcp_layer)
                headers["tcp"] = self._extract_tcp_headers(tcp_layer)
                
                # Extract payload
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    payload_size = len(payload)
                    payload_preview = self._safe_decode_payload(payload[:100])
            
            # UDP specific information
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                dest_port = udp_layer.dport
                protocol = "UDP"
                headers["udp"] = self._extract_udp_headers(udp_layer)
                
                # Extract payload
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    payload_size = len(payload)
                    payload_preview = self._safe_decode_payload(payload[:100])
            
            return PacketInfo(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                packet_size=packet_size,
                ttl=ttl,
                flags=flags,
                payload_size=payload_size,
                payload_preview=payload_preview,
                headers=headers
            )
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def _extract_ip_headers(self, ip_layer) -> Dict:
        """Extract IP header information"""
        return {
            "version": ip_layer.version,
            "ihl": ip_layer.ihl,
            "tos": ip_layer.tos,
            "len": ip_layer.len,
            "id": ip_layer.id,
            "flags": ip_layer.flags,
            "frag": ip_layer.frag,
            "ttl": ip_layer.ttl,
            "proto": ip_layer.proto,
            "chksum": ip_layer.chksum
        }
    
    def _extract_tcp_headers(self, tcp_layer) -> Dict:
        """Extract TCP header information"""
        return {
            "sport": tcp_layer.sport,
            "dport": tcp_layer.dport,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "dataofs": tcp_layer.dataofs,
            "reserved": tcp_layer.reserved,
            "flags": tcp_layer.flags,
            "window": tcp_layer.window,
            "chksum": tcp_layer.chksum,
            "urgptr": tcp_layer.urgptr
        }
    
    def _extract_udp_headers(self, udp_layer) -> Dict:
        """Extract UDP header information"""
        return {
            "sport": udp_layer.sport,
            "dport": udp_layer.dport,
            "len": udp_layer.len,
            "chksum": udp_layer.chksum
        }
    
    def _extract_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string"""
        flags = []
        if tcp_layer.flags & 0x01:  # FIN
            flags.append("FIN")
        if tcp_layer.flags & 0x02:  # SYN
            flags.append("SYN")
        if tcp_layer.flags & 0x04:  # RST
            flags.append("RST")
        if tcp_layer.flags & 0x08:  # PSH
            flags.append("PSH")
        if tcp_layer.flags & 0x10:  # ACK
            flags.append("ACK")
        if tcp_layer.flags & 0x20:  # URG
            flags.append("URG")
        return ",".join(flags)
    
    def _safe_decode_payload(self, payload: bytes) -> str:
        """Safely decode payload to string"""
        try:
            # Try UTF-8 first
            return payload.decode('utf-8', errors='ignore')
        except:
            # Fallback to hex representation
            return binascii.hexlify(payload).decode('ascii')
    
    def _update_flows(self, packet_info: PacketInfo):
        """Update network flow tracking"""
        flow_id = self._generate_flow_id(packet_info)
        
        if flow_id not in self.flows:
            self.flows[flow_id] = FlowInfo(
                flow_id=flow_id,
                source_ip=packet_info.source_ip,
                dest_ip=packet_info.dest_ip,
                source_port=packet_info.source_port,
                dest_port=packet_info.dest_port,
                protocol=packet_info.protocol,
                start_time=packet_info.timestamp,
                end_time=None,
                packet_count=0,
                total_bytes=0,
                flags_seen=[],
                connection_state="UNKNOWN"
            )
        
        flow = self.flows[flow_id]
        flow.packet_count += 1
        flow.total_bytes += packet_info.packet_size
        flow.end_time = packet_info.timestamp
        
        # Track TCP connection state
        if packet_info.protocol == "TCP" and packet_info.flags:
            if packet_info.flags not in flow.flags_seen:
                flow.flags_seen.append(packet_info.flags)
            
            # Simple connection state tracking
            if "SYN" in packet_info.flags and "ACK" not in packet_info.flags:
                flow.connection_state = "SYN_SENT"
            elif "SYN" in packet_info.flags and "ACK" in packet_info.flags:
                flow.connection_state = "ESTABLISHED"
            elif "FIN" in packet_info.flags:
                flow.connection_state = "CLOSING"
            elif "RST" in packet_info.flags:
                flow.connection_state = "RESET"
    
    def _generate_flow_id(self, packet_info: PacketInfo) -> str:
        """Generate unique flow identifier"""
        # Sort IPs to ensure bidirectional flow tracking
        ip1, port1 = packet_info.source_ip, packet_info.source_port
        ip2, port2 = packet_info.dest_ip, packet_info.dest_port
        
        if (ip1, port1) > (ip2, port2):
            ip1, port1, ip2, port2 = ip2, port2, ip1, port1
        
        return f"{packet_info.protocol}_{ip1}:{port1}_{ip2}:{port2}"
    
    def _deep_inspect_packet(self, packet, packet_info: PacketInfo):
        """Perform deep packet inspection"""
        # Identify application protocol based on port
        app_protocol = self._identify_application_protocol(packet_info.dest_port)
        
        if app_protocol in self.protocol_analyzers:
            try:
                analysis = self.protocol_analyzers[app_protocol](packet, packet_info)
                if analysis:
                    packet_info.headers[app_protocol.lower()] = analysis
            except Exception as e:
                print(f"Error in {app_protocol} analysis: {e}")
    
    def _identify_application_protocol(self, port: int) -> str:
        """Identify application protocol by port"""
        port_map = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            53: "DNS", 25: "SMTP", 110: "POP3", 143: "IMAP",
            993: "IMAPS", 995: "POP3S", 587: "SMTP"
        }
        return port_map.get(port, "UNKNOWN")
    
    def _analyze_http(self, packet, packet_info: PacketInfo) -> Optional[Dict]:
        """Analyze HTTP traffic"""
        if not packet.haslayer(Raw):
            return None
        
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # Check if it's HTTP
        if not (payload.startswith('GET ') or payload.startswith('POST ') or 
                payload.startswith('HTTP/')):
            return None
        
        lines = payload.split('\n')
        if not lines:
            return None
        
        analysis = {"protocol": "HTTP"}
        
        # Parse request line or status line
        first_line = lines[0].strip()
        if first_line.startswith('HTTP/'):
            # Response
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                analysis["type"] = "response"
                analysis["version"] = parts[0]
                analysis["status_code"] = parts[1]
                analysis["status_message"] = parts[2]
        else:
            # Request
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                analysis["type"] = "request"
                analysis["method"] = parts[0]
                analysis["uri"] = parts[1]
                analysis["version"] = parts[2]
        
        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif line.strip() == '':
                break
        
        analysis["headers"] = headers
        return analysis
    
    def _analyze_https(self, packet, packet_info: PacketInfo) -> Optional[Dict]:
        """Analyze HTTPS/TLS traffic"""
        if not packet.haslayer(Raw):
            return None
        
        payload = packet[Raw].load
        
        # Check for TLS handshake
        if len(payload) < 6:
            return None
        
        # TLS record header: type(1) + version(2) + length(2)
        record_type = payload[0]
        version = int.from_bytes(payload[1:3], 'big')
        length = int.from_bytes(payload[3:5], 'big')
        
        analysis = {"protocol": "TLS/HTTPS"}
        
        # TLS record types
        record_types = {
            20: "Change Cipher Spec",
            21: "Alert",
            22: "Handshake",
            23: "Application Data"
        }
        
        analysis["record_type"] = record_types.get(record_type, f"Unknown({record_type})")
        analysis["version"] = f"{(version >> 8) & 0xFF}.{version & 0xFF}"
        analysis["length"] = length
        
        # If it's a handshake, try to get more details
        if record_type == 22 and len(payload) > 5:
            handshake_type = payload[5]
            handshake_types = {
                1: "Client Hello",
                2: "Server Hello",
                11: "Certificate",
                12: "Server Key Exchange",
                13: "Certificate Request",
                14: "Server Hello Done",
                15: "Certificate Verify",
                16: "Client Key Exchange",
                20: "Finished"
            }
            analysis["handshake_type"] = handshake_types.get(handshake_type, f"Unknown({handshake_type})")
        
        return analysis
    
    def _analyze_ssh(self, packet, packet_info: PacketInfo) -> Optional[Dict]:
        """Analyze SSH traffic"""
        if not packet.haslayer(Raw):
            return None
        
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        if payload.startswith('SSH-'):
            # SSH version exchange
            return {
                "protocol": "SSH",
                "type": "version_exchange",
                "version_string": payload.strip()
            }
        
        return {"protocol": "SSH", "type": "encrypted_data"}
    
    def _analyze_ftp(self, packet, packet_info: PacketInfo) -> Optional[Dict]:
        """Analyze FTP traffic"""
        if not packet.haslayer(Raw):
            return None
        
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # FTP commands and responses
        if payload.startswith(('USER ', 'PASS ', 'QUIT', 'PWD', 'CWD ', 'LIST')):
            return {
                "protocol": "FTP",
                "type": "command",
                "command": payload.strip()
            }
        elif payload[0].isdigit() and len(payload) >= 3:
            return {
                "protocol": "FTP",
                "type": "response",
                "code": payload[:3],
                "message": payload[4:].strip() if len(payload) > 4 else ""
            }
        
        return None
    
    def _analyze_dns(self, packet, packet_info: PacketInfo) -> Optional[Dict]:
        """Analyze DNS traffic"""
        if not packet.haslayer(UDP):
            return None
        
        # Basic DNS analysis would require more complex parsing
        return {"protocol": "DNS", "type": "query_or_response"}
    
    def _analyze_smtp(self, packet, packet_info: PacketInfo) -> Optional[Dict]:
        """Analyze SMTP traffic"""
        if not packet.haslayer(Raw):
            return None
        
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # SMTP commands
        smtp_commands = ['HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT', 'RSET']
        
        for cmd in smtp_commands:
            if payload.upper().startswith(cmd):
                return {
                    "protocol": "SMTP",
                    "type": "command",
                    "command": cmd,
                    "data": payload.strip()
                }
        
        # SMTP responses (start with 3-digit code)
        if len(payload) >= 3 and payload[:3].isdigit():
            return {
                "protocol": "SMTP",
                "type": "response",
                "code": payload[:3],
                "message": payload[4:].strip() if len(payload) > 4 else ""
            }
        
        return None
    
    def analyze_pcap_file(self, filename: str) -> Dict:
        """Analyze existing pcap file"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for pcap analysis")
        
        print(f"📄 Analyzing pcap file: {filename}")
        
        try:
            packets = rdpcap(filename)
            print(f"Loaded {len(packets)} packets")
            
            # Process each packet
            for packet in packets:
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    self.captured_packets.append(packet_info)
                    self._update_flows(packet_info)
                    
                    if self.config['deep_packet_inspection']:
                        self._deep_inspect_packet(packet, packet_info)
            
            return self.get_analysis_summary()
            
        except Exception as e:
            raise RuntimeError(f"Failed to analyze pcap file: {e}")
    
    def get_analysis_summary(self) -> Dict:
        """Get comprehensive analysis summary"""
        if not self.captured_packets:
            return {"message": "No packets captured or analyzed"}
        
        # Basic statistics
        total_packets = len(self.captured_packets)
        protocols = {}
        ports = {}
        ips = set()
        
        for packet in self.captured_packets:
            protocols[packet.protocol] = protocols.get(packet.protocol, 0) + 1
            ports[packet.dest_port] = ports.get(packet.dest_port, 0) + 1
            ips.add(packet.source_ip)
            ips.add(packet.dest_ip)
        
        # Flow statistics
        flow_stats = {
            "total_flows": len(self.flows),
            "tcp_flows": len([f for f in self.flows.values() if f.protocol == "TCP"]),
            "udp_flows": len([f for f in self.flows.values() if f.protocol == "UDP"]),
            "connection_states": {}
        }
        
        for flow in self.flows.values():
            state = flow.connection_state
            flow_stats["connection_states"][state] = flow_stats["connection_states"].get(state, 0) + 1
        
        # Top talkers
        ip_traffic = {}
        for packet in self.captured_packets:
            ip_traffic[packet.source_ip] = ip_traffic.get(packet.source_ip, 0) + packet.packet_size
        
        top_talkers = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "summary": {
                "total_packets": total_packets,
                "unique_ips": len(ips),
                "capture_duration": self._calculate_capture_duration(),
                "total_bytes": sum(p.packet_size for p in self.captured_packets)
            },
            "protocols": protocols,
            "top_ports": dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            "flows": flow_stats,
            "top_talkers": top_talkers,
            "application_protocols": self._get_application_protocol_stats()
        }
    
    def _calculate_capture_duration(self) -> float:
        """Calculate capture duration in seconds"""
        if len(self.captured_packets) < 2:
            return 0
        
        start_time = min(p.timestamp for p in self.captured_packets)
        end_time = max(p.timestamp for p in self.captured_packets)
        return (end_time - start_time).total_seconds()
    
    def _get_application_protocol_stats(self) -> Dict:
        """Get statistics for detected application protocols"""
        app_protocols = {}
        
        for packet in self.captured_packets:
            for header_type in packet.headers:
                if header_type not in ['ip', 'tcp', 'udp']:
                    app_protocols[header_type] = app_protocols.get(header_type, 0) + 1
        
        return app_protocols
    
    def export_analysis(self, filename: str = None) -> str:
        """Export analysis results to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_analysis_{timestamp}.json"
        
        export_data = {
            "analysis_timestamp": datetime.now().isoformat(),
            "config": self.config,
            "summary": self.get_analysis_summary(),
            "packets": [asdict(packet) for packet in self.captured_packets[-1000:]],  # Last 1000 packets
            "flows": [asdict(flow) for flow in list(self.flows.values())[-100:]]  # Last 100 flows
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"📄 Analysis exported to {filename}")
        return filename

def main():
    """Demo packet capture functionality"""
    print("📡 Packet Capture and Analysis Tool - Demo")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not available. Please install with: pip install scapy")
        return
    
    # Initialize analyzer
    analyzer = PacketCaptureAnalyzer()
    
    # Add real-time analysis callback
    def print_packet_info(packet_info: PacketInfo):
        print(f"📦 {packet_info.timestamp.strftime('%H:%M:%S')} - "
              f"{packet_info.source_ip}:{packet_info.source_port} → "
              f"{packet_info.dest_ip}:{packet_info.dest_port} "
              f"({packet_info.protocol}) [{packet_info.packet_size} bytes]")
    
    analyzer.add_analysis_callback(print_packet_info)
    
    try:
        print("Starting 30-second packet capture...")
        pcap_file = analyzer.start_capture(duration=30)
        
        print("\n📊 Analysis Summary:")
        summary = analyzer.get_analysis_summary()
        
        for section, data in summary.items():
            print(f"\n{section.upper()}:")
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {data}")
        
        # Export results
        export_file = analyzer.export_analysis()
        print(f"\n💾 Results exported to {export_file}")
        
    except KeyboardInterrupt:
        print("\n⚠️  Capture interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()

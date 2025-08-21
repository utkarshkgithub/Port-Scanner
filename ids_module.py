"""
Intrusion Detection System (IDS) Module
Lightweight IDS for detecting network anomalies and attack patterns
"""

import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Optional, Tuple
import statistics
import socket

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@dataclass
class ConnectionEvent:
    """Data class for tracking connection events"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    packet_size: int
    flags: str = ""

@dataclass
class IDSAlert:
    """Enhanced IDS alert data class"""
    alert_id: str
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    destination_port: int
    timestamp: datetime
    description: str
    confidence: float
    metadata: Dict
    rule_triggered: str

class NetworkIDSLite:
    """Lightweight Intrusion Detection System"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.alerts = []
        self.connection_tracker = defaultdict(deque)
        self.ip_stats = defaultdict(lambda: {
            'connections': deque(),
            'bytes_sent': deque(),
            'ports_accessed': set(),
            'last_activity': None
        })
        self.baseline_metrics = {}
        self.running = False
        self.alert_callbacks = []
        
        # Signature-based detection rules
        self.signatures = {
            'port_scan': {
                'description': 'Multiple port access from single IP',
                'threshold': 10,
                'time_window': 30,
                'severity': 'medium'
            },
            'syn_flood': {
                'description': 'High rate of SYN packets',
                'threshold': 100,
                'time_window': 10,
                'severity': 'high'
            },
            'suspicious_ports': {
                'description': 'Access to suspicious ports',
                'ports': [1234, 31337, 12345, 54321, 9999],
                'severity': 'medium'
            },
            'rapid_connections': {
                'description': 'Rapid connection attempts',
                'threshold': 50,
                'time_window': 60,
                'severity': 'medium'
            },
            'large_payload': {
                'description': 'Unusually large packet payload',
                'threshold': 8000,
                'severity': 'low'
            }
        }
    
    def _default_config(self) -> Dict:
        """Default IDS configuration"""
        return {
            'monitoring_interface': None,  # Will auto-detect interface
            'alert_threshold': 'low',
            'baseline_learning_period': 300,  # 5 minutes
            'max_alerts_per_minute': 10,
            'log_file': 'ids_alerts.json',
            'enable_packet_capture': False,
            'capture_filter': 'tcp',
            'anomaly_detection': True
        }
    
    def add_alert_callback(self, callback):
        """Add callback function for real-time alerts"""
        self.alert_callbacks.append(callback)
    
    def process_connection_event(self, event: ConnectionEvent):
        """Process a new connection event for analysis"""
        current_time = event.timestamp
        source_ip = event.source_ip
        
        # Update IP statistics
        self._update_ip_stats(event)
        
        # Check signature-based rules
        self._check_signatures(event)
        
        # Anomaly detection
        if self.config['anomaly_detection']:
            self._check_anomalies(event)
    
    def _update_ip_stats(self, event: ConnectionEvent):
        """Update statistics for the source IP"""
        source_ip = event.source_ip
        current_time = event.timestamp
        
        stats = self.ip_stats[source_ip]
        stats['last_activity'] = current_time
        stats['connections'].append(current_time)
        stats['bytes_sent'].append(event.packet_size)
        stats['ports_accessed'].add(event.dest_port)
        
        # Clean old data (keep last hour)
        cutoff_time = current_time - timedelta(hours=1)
        while stats['connections'] and stats['connections'][0] < cutoff_time:
            stats['connections'].popleft()
        while stats['bytes_sent'] and len(stats['bytes_sent']) > len(stats['connections']):
            stats['bytes_sent'].popleft()
    
    def _check_signatures(self, event: ConnectionEvent):
        """Check event against signature-based rules"""
        source_ip = event.source_ip
        current_time = event.timestamp
        
        # Port scan detection
        self._check_port_scan(source_ip, current_time)
        
        # Suspicious ports
        if event.dest_port in self.signatures['suspicious_ports']['ports']:
            self._create_alert(
                'suspicious_ports',
                source_ip,
                event.dest_ip,
                event.dest_port,
                f"Access to suspicious port {event.dest_port}",
                self.signatures['suspicious_ports']['severity'],
                0.8,
                {'port': event.dest_port}
            )
        
        # Large payload detection
        if event.packet_size > self.signatures['large_payload']['threshold']:
            self._create_alert(
                'large_payload',
                source_ip,
                event.dest_ip,
                event.dest_port,
                f"Large packet payload: {event.packet_size} bytes",
                self.signatures['large_payload']['severity'],
                0.6,
                {'packet_size': event.packet_size}
            )
        
        # Rapid connections
        self._check_rapid_connections(source_ip, current_time)
    
    def _check_port_scan(self, source_ip: str, current_time: datetime):
        """Check for port scanning behavior"""
        stats = self.ip_stats[source_ip]
        time_window = timedelta(seconds=self.signatures['port_scan']['time_window'])
        cutoff_time = current_time - time_window
        
        # Count unique ports accessed in time window
        recent_connections = [t for t in stats['connections'] if t >= cutoff_time]
        unique_ports = len(stats['ports_accessed'])
        
        if unique_ports >= self.signatures['port_scan']['threshold']:
            self._create_alert(
                'port_scan',
                source_ip,
                '',
                0,
                f"Port scan detected: {unique_ports} unique ports accessed",
                self.signatures['port_scan']['severity'],
                0.9,
                {
                    'unique_ports': unique_ports,
                    'connections_in_window': len(recent_connections),
                    'ports_list': list(stats['ports_accessed'])
                }
            )
    
    def _check_rapid_connections(self, source_ip: str, current_time: datetime):
        """Check for rapid connection attempts"""
        stats = self.ip_stats[source_ip]
        time_window = timedelta(seconds=self.signatures['rapid_connections']['time_window'])
        cutoff_time = current_time - time_window
        
        recent_connections = [t for t in stats['connections'] if t >= cutoff_time]
        
        if len(recent_connections) >= self.signatures['rapid_connections']['threshold']:
            self._create_alert(
                'rapid_connections',
                source_ip,
                '',
                0,
                f"Rapid connections: {len(recent_connections)} in {self.signatures['rapid_connections']['time_window']}s",
                self.signatures['rapid_connections']['severity'],
                0.7,
                {
                    'connection_count': len(recent_connections),
                    'time_window': self.signatures['rapid_connections']['time_window']
                }
            )
    
    def _check_anomalies(self, event: ConnectionEvent):
        """Check for statistical anomalies"""
        source_ip = event.source_ip
        stats = self.ip_stats[source_ip]
        
        if len(stats['connections']) < 10:  # Need baseline data
            return
        
        # Calculate connection rate anomaly
        current_hour_connections = len([
            t for t in stats['connections'] 
            if t >= event.timestamp - timedelta(hours=1)
        ])
        
        # Simple anomaly: more than 3 standard deviations from mean
        if source_ip in self.baseline_metrics:
            baseline = self.baseline_metrics[source_ip]
            if current_hour_connections > baseline.get('mean_hourly_connections', 0) + 3 * baseline.get('std_hourly_connections', 1):
                self._create_alert(
                    'anomaly_high_connection_rate',
                    source_ip,
                    event.dest_ip,
                    event.dest_port,
                    f"Anomalously high connection rate: {current_hour_connections}/hour",
                    'medium',
                    0.6,
                    {
                        'current_rate': current_hour_connections,
                        'baseline_mean': baseline.get('mean_hourly_connections', 0),
                        'baseline_std': baseline.get('std_hourly_connections', 1)
                    }
                )
    
    def _create_alert(self, alert_type: str, source_ip: str, dest_ip: str, 
                     dest_port: int, description: str, severity: str, 
                     confidence: float, metadata: Dict):
        """Create and store an IDS alert"""
        alert_id = f"{alert_type}_{source_ip}_{int(time.time())}"
        
        alert = IDSAlert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=dest_ip,
            destination_port=dest_port,
            timestamp=datetime.now(),
            description=description,
            confidence=confidence,
            metadata=metadata,
            rule_triggered=alert_type
        )
        
        self.alerts.append(alert)
        
        # Call registered callbacks
        for callback in self.alert_callbacks:
            callback(alert)
        
        # Log to file
        self._log_alert(alert)
    
    def _log_alert(self, alert: IDSAlert):
        """Log alert to file"""
        try:
            with open(self.config['log_file'], 'a') as f:
                json.dump(asdict(alert), f, default=str)
                f.write('\n')
        except Exception as e:
            print(f"Failed to log alert: {e}")
    
    def generate_baseline(self, duration_minutes: int = 5):
        """Generate baseline metrics for anomaly detection"""
        print(f"Learning baseline for {duration_minutes} minutes...")
        
        if SCAPY_AVAILABLE:
            # Capture packets for baseline learning
            packets = sniff(timeout=duration_minutes * 60, filter="tcp")
            
            for packet in packets:
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    event = self._packet_to_event(packet)
                    if event:
                        self.process_connection_event(event)
        
        # Calculate baseline metrics
        for ip, stats in self.ip_stats.items():
            if len(stats['connections']) >= 5:  # Minimum data points
                hourly_rates = []
                # Calculate hourly connection rates
                for i in range(len(stats['connections']) - 4):
                    hour_start = stats['connections'][i]
                    hour_end = hour_start + timedelta(hours=1)
                    connections_in_hour = len([
                        t for t in stats['connections'][i:] 
                        if hour_start <= t <= hour_end
                    ])
                    hourly_rates.append(connections_in_hour)
                
                if hourly_rates:
                    self.baseline_metrics[ip] = {
                        'mean_hourly_connections': statistics.mean(hourly_rates),
                        'std_hourly_connections': statistics.stdev(hourly_rates) if len(hourly_rates) > 1 else 1,
                        'baseline_generated': datetime.now()
                    }
        
        print(f"Baseline generated for {len(self.baseline_metrics)} IP addresses")
    
    def _packet_to_event(self, packet) -> Optional[ConnectionEvent]:
        """Convert Scapy packet to ConnectionEvent"""
        try:
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                return None
            
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            
            flags = ""
            if tcp_layer.flags & 0x02:  # SYN
                flags += "S"
            if tcp_layer.flags & 0x10:  # ACK
                flags += "A"
            if tcp_layer.flags & 0x01:  # FIN
                flags += "F"
            if tcp_layer.flags & 0x04:  # RST
                flags += "R"
            
            return ConnectionEvent(
                timestamp=datetime.now(),
                source_ip=ip_layer.src,
                dest_ip=ip_layer.dst,
                dest_port=tcp_layer.dport,
                protocol="TCP",
                packet_size=len(packet),
                flags=flags
            )
        except Exception:
            return None
    
    def start_monitoring(self, interface: str = None):
        """Start real-time network monitoring"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot start real-time monitoring.")
            return
        
        self.running = True
        
        # Auto-detect interface if not specified
        if interface is None:
            interface = self.config['monitoring_interface']
        
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
        
        def packet_handler(packet):
            if not self.running:
                return
            
            event = self._packet_to_event(packet)
            if event:
                self.process_connection_event(event)
        
        print(f"Starting IDS monitoring on interface: {interface}")
        try:
            sniff(iface=interface, prn=packet_handler, filter=self.config['capture_filter'], store=0)
        except Exception as e:
            print(f"Error in packet capture: {e}")
        finally:
            self.running = False
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        print("IDS monitoring stopped")
    
    def get_alert_summary(self) -> Dict:
        """Get summary of all alerts"""
        if not self.alerts:
            return {"total_alerts": 0}
        
        alert_types = defaultdict(int)
        severity_counts = defaultdict(int)
        source_ips = defaultdict(int)
        
        for alert in self.alerts:
            alert_types[alert.alert_type] += 1
            severity_counts[alert.severity] += 1
            source_ips[alert.source_ip] += 1
        
        return {
            "total_alerts": len(self.alerts),
            "alert_types": dict(alert_types),
            "severity_distribution": dict(severity_counts),
            "top_source_ips": dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            "time_range": {
                "first_alert": min(alert.timestamp for alert in self.alerts),
                "last_alert": max(alert.timestamp for alert in self.alerts)
            }
        }
    
    def export_alerts(self, filename: str = None) -> str:
        """Export all alerts to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ids_alerts_export_{timestamp}.json"
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "config": self.config,
            "summary": self.get_alert_summary(),
            "alerts": [asdict(alert) for alert in self.alerts]
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return filename

def main():
    """Demo IDS functionality"""
    print("🛡️  Network IDS Lite - Demo Mode")
    
    # Initialize IDS
    ids = NetworkIDSLite()
    
    # Add alert callback for demo
    def print_alert(alert: IDSAlert):
        print(f"🚨 ALERT: {alert.alert_type} from {alert.source_ip} - {alert.description}")
    
    ids.add_alert_callback(print_alert)
    
    # Simulate some events for demo
    print("Simulating network events...")
    
    # Simulate port scan
    for port in range(80, 95):
        event = ConnectionEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.10",
            dest_port=port,
            protocol="TCP",
            packet_size=64
        )
        ids.process_connection_event(event)
        time.sleep(0.1)
    
    # Simulate suspicious port access
    event = ConnectionEvent(
        timestamp=datetime.now(),
        source_ip="192.168.1.200",
        dest_ip="192.168.1.10",
        dest_port=31337,
        protocol="TCP",
        packet_size=128
    )
    ids.process_connection_event(event)
    
    # Print summary
    print("\n📊 Alert Summary:")
    summary = ids.get_alert_summary()
    for key, value in summary.items():
        print(f"{key}: {value}")
    
    # Export alerts
    filename = ids.export_alerts()
    print(f"\n💾 Alerts exported to: {filename}")

if __name__ == "__main__":
    main()

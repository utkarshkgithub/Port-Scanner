"""
Network Diagnostic Tool - Core Module
Enhanced port scanner with banner grabbing, traceroute, and IDS functionality
"""

import socket
import sys
import time
import threading
import json
import struct
import random
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import argparse

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some features will be limited.")

from colorama import Fore, Back, Style, init
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID
from rich import print as rprint

# Initialize colorama
init(autoreset=True)
console = Console()

@dataclass
class PortScanResult:
    """Data class for port scan results"""
    port: int
    status: str  # 'open', 'closed', 'filtered'
    service: str
    banner: str
    response_time: float
    timestamp: datetime

@dataclass
class TracerouteHop:
    """Data class for traceroute hop information"""
    hop_number: int
    ip_address: str
    hostname: str
    rtt_ms: float
    ttl: int

@dataclass
class SecurityAlert:
    """Data class for security alerts"""
    alert_type: str
    source_ip: str
    timestamp: datetime
    severity: str
    description: str
    metadata: Dict[str, Any]

class NetworkDiagnosticTool:
    """Enhanced network diagnostic tool with comprehensive scanning capabilities"""
    
    def __init__(self):
        self.results = []
        self.traceroute_results = []
        self.security_alerts = []
        self.connection_tracker = defaultdict(list)
        self.scan_start_time = None
        self.ids_enabled = True
        
        # Enhanced port-service mapping
        self.port_service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            9200: "Elasticsearch", 27017: "MongoDB", 5984: "CouchDB", 11211: "Memcached"
        }
        
        # Signature patterns for IDS
        self.attack_signatures = {
            'port_scan': {'threshold': 10, 'time_window': 30},
            'syn_flood': {'threshold': 100, 'time_window': 10},
            'suspicious_connections': {'threshold': 50, 'time_window': 60}
        }

    def banner_grab(self, target: str, port: int, timeout: int = 3) -> str:
        """Grab service banner from target port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send common probes based on port
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner immediately
            elif port == 22:
                pass  # SSH sends banner immediately
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            elif port == 110:
                sock.send(b"USER test\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]  # Limit banner length
        except:
            return ""

    def scan_port(self, target: str, port: int) -> PortScanResult:
        """Enhanced port scanning with banner grabbing and classification"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            response_time = (time.time() - start_time) * 1000
            
            if result == 0:
                # Port is open
                banner = self.banner_grab(target, port)
                service = self.port_service_map.get(port, "Unknown")
                status = "open"
            else:
                banner = ""
                service = ""
                status = "closed"
            
            sock.close()
            
        except socket.timeout:
            # Likely filtered by firewall
            status = "filtered"
            banner = ""
            service = ""
            response_time = 2000
        except Exception:
            status = "closed"
            banner = ""
            service = ""
            response_time = (time.time() - start_time) * 1000
        
        return PortScanResult(
            port=port,
            status=status,
            service=service,
            banner=banner,
            response_time=response_time,
            timestamp=datetime.now()
        )

    def traceroute(self, target: str, max_hops: int = 30) -> List[TracerouteHop]:
        """Perform traceroute with TTL-based hop detection"""
        hops = []
        
        if not SCAPY_AVAILABLE:
            # Fallback to system traceroute
            return self._system_traceroute(target, max_hops)
        
        target_ip = socket.gethostbyname(target)
        
        for ttl in range(1, max_hops + 1):
            start_time = time.time()
            
            # Create ICMP packet with specific TTL
            packet = IP(dst=target_ip, ttl=ttl) / ICMP()
            
            try:
                reply = sr1(packet, timeout=3, verbose=0)
                rtt = (time.time() - start_time) * 1000
                
                if reply:
                    hop_ip = reply.src
                    try:
                        hostname = socket.gethostbyaddr(hop_ip)[0]
                    except:
                        hostname = hop_ip
                    
                    hop = TracerouteHop(
                        hop_number=ttl,
                        ip_address=hop_ip,
                        hostname=hostname,
                        rtt_ms=rtt,
                        ttl=ttl
                    )
                    hops.append(hop)
                    
                    # Check if we reached the target
                    if hop_ip == target_ip:
                        break
                else:
                    # No reply - likely timeout
                    hop = TracerouteHop(
                        hop_number=ttl,
                        ip_address="*",
                        hostname="*",
                        rtt_ms=0,
                        ttl=ttl
                    )
                    hops.append(hop)
                    
            except Exception as e:
                console.print(f"[red]Error in traceroute hop {ttl}: {e}[/red]")
                continue
                
        return hops

    def _system_traceroute(self, target: str, max_hops: int) -> List[TracerouteHop]:
        """Fallback traceroute using system command"""
        hops = []
        try:
            result = subprocess.run(['traceroute', '-m', str(max_hops), target], 
                                  capture_output=True, text=True, timeout=60)
            
            for i, line in enumerate(result.stdout.split('\n')[1:], 1):
                if not line.strip():
                    continue
                    
                # Parse traceroute output
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        hop_num = int(parts[0])
                        ip_or_host = parts[1]
                        rtt_str = parts[2] if 'ms' in parts[2] else '0'
                        rtt = float(rtt_str.replace('ms', ''))
                        
                        hop = TracerouteHop(
                            hop_number=hop_num,
                            ip_address=ip_or_host,
                            hostname=ip_or_host,
                            rtt_ms=rtt,
                            ttl=hop_num
                        )
                        hops.append(hop)
                    except (ValueError, IndexError):
                        continue
                        
        except subprocess.TimeoutExpired:
            console.print("[red]Traceroute timeout[/red]")
        except FileNotFoundError:
            console.print("[red]Traceroute command not found[/red]")
            
        return hops

    def detect_port_scan(self, source_ip: str) -> bool:
        """Detect potential port scanning behavior"""
        current_time = time.time()
        threshold = self.attack_signatures['port_scan']['threshold']
        time_window = self.attack_signatures['port_scan']['time_window']
        
        # Clean old entries
        cutoff_time = current_time - time_window
        self.connection_tracker[source_ip] = [
            t for t in self.connection_tracker[source_ip] if t > cutoff_time
        ]
        
        # Add current connection
        self.connection_tracker[source_ip].append(current_time)
        
        # Check if threshold exceeded
        if len(self.connection_tracker[source_ip]) > threshold:
            self._create_alert('port_scan', source_ip, 
                             f"Potential port scan detected: {len(self.connection_tracker[source_ip])} connections in {time_window}s")
            return True
        return False

    def _create_alert(self, alert_type: str, source_ip: str, description: str, severity: str = "medium"):
        """Create and store security alert"""
        alert = SecurityAlert(
            alert_type=alert_type,
            source_ip=source_ip,
            timestamp=datetime.now(),
            severity=severity,
            description=description,
            metadata={"connection_count": len(self.connection_tracker[source_ip])}
        )
        self.security_alerts.append(alert)
        
        # Print alert to console
        color = Fore.RED if severity == "high" else Fore.YELLOW
        console.print(f"[bold red]🚨 SECURITY ALERT[/bold red]: {alert_type.upper()}")
        console.print(f"Source: {source_ip}")
        console.print(f"Description: {description}")
        console.print(f"Time: {alert.timestamp}")
        print()

    def comprehensive_scan(self, target: str, start_port: int, end_port: int, 
                          enable_traceroute: bool = True, threads: int = 50) -> Dict:
        """Perform comprehensive network diagnostic scan"""
        self.scan_start_time = time.time()
        console.print(f"[bold green]🔍 Starting comprehensive scan of {target}[/bold green]")
        console.print(f"Port range: {start_port}-{end_port}")
        print()
        
        # Resolve target
        try:
            target_ip = socket.gethostbyname(target)
            console.print(f"Target IP: {target_ip}")
        except socket.gaierror:
            console.print("[red]❌ Name resolution failed[/red]")
            return {}
        
        # Traceroute
        if enable_traceroute:
            console.print("[yellow]🛣️  Running traceroute...[/yellow]")
            self.traceroute_results = self.traceroute(target)
            self._display_traceroute_results()
        
        # Port scanning with progress bar
        console.print("[yellow]🔎 Scanning ports...[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("[green]Scanning...", total=end_port-start_port+1)
            
            def scan_with_progress(port):
                result = self.scan_port(target_ip, port)
                self.results.append(result)
                
                # IDS monitoring
                if self.ids_enabled and result.status == "open":
                    self.detect_port_scan(target_ip)
                
                progress.update(task, advance=1)
            
            # Multi-threaded scanning
            thread_list = []
            for port in range(start_port, end_port + 1):
                if len(thread_list) >= threads:
                    # Wait for some threads to complete
                    for t in thread_list[:threads//2]:
                        t.join()
                    thread_list = thread_list[threads//2:]
                
                thread = threading.Thread(target=scan_with_progress, args=(port,))
                thread_list.append(thread)
                thread.start()
            
            # Wait for remaining threads
            for thread in thread_list:
                thread.join()
        
        # Display results
        self._display_scan_results()
        
        # Generate summary
        scan_summary = self._generate_summary()
        
        return scan_summary

    def _display_traceroute_results(self):
        """Display traceroute results in a formatted table"""
        if not self.traceroute_results:
            return
            
        table = Table(title="Traceroute Results")
        table.add_column("Hop", style="cyan", no_wrap=True)
        table.add_column("IP Address", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("RTT (ms)", style="yellow")
        
        for hop in self.traceroute_results:
            rtt_str = f"{hop.rtt_ms:.2f}" if hop.rtt_ms > 0 else "*"
            table.add_row(
                str(hop.hop_number),
                hop.ip_address,
                hop.hostname,
                rtt_str
            )
        
        console.print(table)
        print()

    def _display_scan_results(self):
        """Display port scan results in a formatted table"""
        if not self.results:
            return
            
        # Filter and sort results
        open_ports = [r for r in self.results if r.status == "open"]
        filtered_ports = [r for r in self.results if r.status == "filtered"]
        
        if open_ports:
            table = Table(title="Open Ports")
            table.add_column("Port", style="cyan", no_wrap=True)
            table.add_column("Service", style="green")
            table.add_column("Banner", style="yellow")
            table.add_column("Response Time (ms)", style="magenta")
            
            for result in sorted(open_ports, key=lambda x: x.port):
                banner_preview = (result.banner[:50] + "...") if len(result.banner) > 50 else result.banner
                table.add_row(
                    str(result.port),
                    result.service,
                    banner_preview,
                    f"{result.response_time:.2f}"
                )
            
            console.print(table)
        
        if filtered_ports:
            console.print(f"\n[yellow]🛡️  {len(filtered_ports)} ports appear to be filtered (likely firewall)[/yellow]")
        
        print()

    def _generate_summary(self) -> Dict:
        """Generate comprehensive scan summary"""
        open_ports = [r for r in self.results if r.status == "open"]
        closed_ports = [r for r in self.results if r.status == "closed"]
        filtered_ports = [r for r in self.results if r.status == "filtered"]
        
        scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        summary = {
            "scan_info": {
                "start_time": self.scan_start_time,
                "duration_seconds": scan_time,
                "total_ports_scanned": len(self.results)
            },
            "port_summary": {
                "open": len(open_ports),
                "closed": len(closed_ports),
                "filtered": len(filtered_ports)
            },
            "open_ports": [asdict(result) for result in open_ports],
            "traceroute": [asdict(hop) for hop in self.traceroute_results],
            "security_alerts": [asdict(alert) for alert in self.security_alerts],
            "services_detected": list(set(r.service for r in open_ports if r.service))
        }
        
        return summary

    def save_results(self, filename: str = None):
        """Save scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.json"
        
        summary = self._generate_summary()
        
        try:
            with open(filename, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            console.print(f"[green]✅ Results saved to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Failed to save results: {e}[/red]")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description="Network Diagnostic Tool - Enhanced Port Scanner")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--no-traceroute", action="store_true", help="Disable traceroute")
    parser.add_argument("--output", "-o", help="Output filename for JSON results")
    parser.add_argument("--no-ids", action="store_true", help="Disable IDS monitoring")
    
    args = parser.parse_args()
    
    # Validate port range
    if args.start_port > args.end_port:
        console.print("[red]❌ Start port must be less than or equal to end port[/red]")
        sys.exit(1)
    
    if not (1 <= args.start_port <= 65535) or not (1 <= args.end_port <= 65535):
        console.print("[red]❌ Port numbers must be between 1 and 65535[/red]")
        sys.exit(1)
    
    # Initialize tool
    tool = NetworkDiagnosticTool()
    if args.no_ids:
        tool.ids_enabled = False
    
    try:
        # Run comprehensive scan
        results = tool.comprehensive_scan(
            target=args.target,
            start_port=args.start_port,
            end_port=args.end_port,
            enable_traceroute=not args.no_traceroute,
            threads=args.threads
        )
        
        # Save results
        tool.save_results(args.output)
        
        # Print summary
        console.print(f"\n[bold green]📊 Scan Summary[/bold green]")
        console.print(f"Total ports scanned: {results['scan_info']['total_ports_scanned']}")
        console.print(f"Open ports: {results['port_summary']['open']}")
        console.print(f"Filtered ports: {results['port_summary']['filtered']}")
        console.print(f"Scan duration: {results['scan_info']['duration_seconds']:.2f} seconds")
        
        if results['security_alerts']:
            console.print(f"[red]🚨 Security alerts: {len(results['security_alerts'])}[/red]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Error during scan: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()

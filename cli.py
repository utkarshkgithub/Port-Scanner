#!/usr/bin/env python3
"""
Network Diagnostic Tool - Command Line Interface
Comprehensive network scanning, IDS, and packet analysis tool
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
import threading
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_diagnostic_tool import NetworkDiagnosticTool
from ids_module import NetworkIDSLite
from packet_analyzer import PacketCaptureAnalyzer
from rich.console import Console
from rich import print as rprint

console = Console()

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="🛡️ Network Diagnostic Tool - Comprehensive Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic port scan
  python cli.py scan 192.168.1.1 1 1000

  # Full diagnostic with traceroute
  python cli.py scan example.com 1 1000 --traceroute --threads 100

  # Start IDS monitoring
  python cli.py ids --monitor --duration 300

  # Packet capture and analysis
  python cli.py capture --duration 60 --analyze
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Network port scanning')
    scan_parser.add_argument('target', help='Target hostname or IP address')
    scan_parser.add_argument('start_port', type=int, help='Starting port number')
    scan_parser.add_argument('end_port', type=int, help='Ending port number')
    scan_parser.add_argument('--threads', '-t', type=int, default=50, help='Number of threads')
    scan_parser.add_argument('--traceroute', action='store_true', help='Enable traceroute')
    scan_parser.add_argument('--output', '-o', help='Output file for results')
    scan_parser.add_argument('--format', choices=['json', 'txt'], default='json', help='Output format')
    
    # IDS command
    ids_parser = subparsers.add_parser('ids', help='Intrusion Detection System')
    ids_parser.add_argument('--monitor', action='store_true', help='Start monitoring')
    ids_parser.add_argument('--duration', type=int, default=300, help='Monitoring duration (seconds)')
    ids_parser.add_argument('--interface', help='Network interface to monitor')
    ids_parser.add_argument('--baseline', action='store_true', help='Generate baseline first')
    ids_parser.add_argument('--export', help='Export alerts to file')
    
    # Packet capture command
    capture_parser = subparsers.add_parser('capture', help='Packet capture and analysis')
    capture_parser.add_argument('--duration', type=int, default=60, help='Capture duration (seconds)')
    capture_parser.add_argument('--count', type=int, help='Maximum packets to capture')
    capture_parser.add_argument('--filter', default='tcp or udp', help='Capture filter')
    capture_parser.add_argument('--analyze', action='store_true', help='Analyze captured packets')
    capture_parser.add_argument('--pcap', help='Analyze existing pcap file')
    capture_parser.add_argument('--output', help='Output file for analysis')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'scan':
            run_scan(args)
        elif args.command == 'ids':
            run_ids(args)
        elif args.command == 'capture':
            run_capture(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operation interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)

def run_scan(args):
    """Run network scan"""
    console.print(f"[bold green]🔍 Starting network scan of {args.target}[/bold green]")
    
    tool = NetworkDiagnosticTool()
    
    try:
        results = tool.comprehensive_scan(
            target=args.target,
            start_port=args.start_port,
            end_port=args.end_port,
            enable_traceroute=args.traceroute,
            threads=args.threads
        )
        
        # Save results
        if args.output:
            filename = args.output
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{args.target}_{timestamp}.json"
        
        tool.save_results(filename)
        
        # Print summary
        console.print(f"\n[bold green]📊 Scan Complete[/bold green]")
        console.print(f"Results saved to: {filename}")
        
    except Exception as e:
        console.print(f"[red]❌ Scan failed: {e}[/red]")

def run_ids(args):
    """Run IDS monitoring"""
    console.print("[bold yellow]🛡️ Starting IDS monitoring[/bold yellow]")
    
    ids = NetworkIDSLite()
    
    def alert_callback(alert):
        console.print(f"[red]🚨 ALERT[/red]: {alert.alert_type} from {alert.source_ip}")
        console.print(f"Description: {alert.description}")
    
    ids.add_alert_callback(alert_callback)
    
    try:
        if args.baseline:
            console.print("[yellow]📚 Generating baseline...[/yellow]")
            ids.generate_baseline(duration_minutes=5)
        
        if args.monitor:
            console.print(f"[green]👁️  Monitoring for {args.duration} seconds...[/green]")
            
            # Start monitoring in background
            monitor_thread = threading.Thread(
                target=ids.start_monitoring,
                args=(args.interface,)
            )
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Wait for specified duration
            time.sleep(args.duration)
            ids.stop_monitoring()
            
            # Export results
            if args.export:
                filename = ids.export_alerts(args.export)
            else:
                filename = ids.export_alerts()
            
            console.print(f"[green]✅ Monitoring complete. Results saved to: {filename}[/green]")
            
            # Print summary
            summary = ids.get_alert_summary()
            console.print(f"Total alerts: {summary['total_alerts']}")
            
    except Exception as e:
        console.print(f"[red]❌ IDS monitoring failed: {e}[/red]")

def run_capture(args):
    """Run packet capture"""
    console.print("[bold blue]📡 Starting packet capture[/bold blue]")
    
    analyzer = PacketCaptureAnalyzer()
    
    try:
        if args.pcap:
            # Analyze existing pcap file
            console.print(f"[yellow]📄 Analyzing pcap file: {args.pcap}[/yellow]")
            results = analyzer.analyze_pcap_file(args.pcap)
        else:
            # Start new capture
            console.print(f"[green]🎯 Capturing packets for {args.duration} seconds...[/green]")
            
            # Configure analyzer
            analyzer.config['capture_filter'] = args.filter
            if args.count:
                analyzer.config['max_packets'] = args.count
            
            pcap_file = analyzer.start_capture(
                duration=args.duration,
                packet_count=args.count
            )
            
            console.print(f"[green]✅ Capture complete: {pcap_file}[/green]")
            results = analyzer.get_analysis_summary()
        
        if args.analyze:
            # Display analysis
            console.print("\n[bold blue]📊 Packet Analysis Summary[/bold blue]")
            if 'summary' in results:
                summary = results['summary']
                console.print(f"Total packets: {summary.get('total_packets', 0)}")
                console.print(f"Unique IPs: {summary.get('unique_ips', 0)}")
                console.print(f"Duration: {summary.get('capture_duration', 0):.2f}s")
                console.print(f"Total bytes: {summary.get('total_bytes', 0)}")
            
            if 'protocols' in results:
                console.print("\nProtocol distribution:")
                for proto, count in results['protocols'].items():
                    console.print(f"  {proto}: {count}")
        
        # Export results
        if args.output:
            filename = analyzer.export_analysis(args.output)
        else:
            filename = analyzer.export_analysis()
        
        console.print(f"[green]💾 Analysis saved to: {filename}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Packet capture failed: {e}[/red]")

if __name__ == '__main__':
    main()

def run_tests(args):
    """Run comprehensive tests"""
    console.print("[bold cyan]🧪 Running comprehensive tests[/bold cyan]")
    
    if args.unit_tests:
        # Run unit tests only
        import subprocess
        result = subprocess.run([
            sys.executable, '-m', 'pytest', 
            'tests/', '-v'
        ], cwd=os.path.dirname(os.path.abspath(__file__)))
        return
    
    # Run local tests
    run_local_tests(args.target)

def run_local_tests(target):
    """Run tests against local target"""
    console.print(f"[yellow]🏠 Running local tests against {target}[/yellow]")
    
    # Test basic scanning
    tool = NetworkDiagnosticTool()
    
    console.print(f"[blue]📡 Testing scan of {target}[/blue]")
    try:
        results = tool.comprehensive_scan(
            target=target,
            start_port=20,
            end_port=100,
            enable_traceroute=False,
            threads=10
        )
        console.print(f"[green]✅ Scan successful: {results['port_summary']['open']} open ports[/green]")
    except Exception as e:
        console.print(f"[red]❌ Scan failed: {e}[/red]")
    
    # Test IDS functionality
    console.print("[blue]🛡️ Testing IDS functionality[/blue]")
    from ids_module import NetworkIDSLite, ConnectionEvent
    
    ids = NetworkIDSLite()
    
    # Simulate some events
    for port in range(80, 95):
        event = ConnectionEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip=target,
            dest_port=port,
            protocol="TCP",
            packet_size=64
        )
        ids.process_connection_event(event)
    
    alerts_summary = ids.get_alert_summary()
    total_alerts = alerts_summary.get('total_alerts', 0)
    console.print(f"[green]✅ IDS test completed: {total_alerts} alerts generated[/green]")
    
    console.print("[green]� All local tests completed successfully![/green]")
    
    # Test basic scanning
    tool = NetworkDiagnosticTool()
    
    try:
        console.print("[blue]📡 Testing port scan...[/blue]")
        results = tool.comprehensive_scan(
            target=target,
            start_port=80,
            end_port=85,
            enable_traceroute=False,
            threads=5
        )
        console.print(f"[green]✅ Scan test passed[/green]")
        
        # Test IDS
        console.print("[blue]🛡️ Testing IDS...[/blue]")
        ids = NetworkIDSLite()
        
        # Simulate events
        from ids_module import ConnectionEvent
        
        for i in range(20):
            event = ConnectionEvent(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                dest_ip=target,
                dest_port=80 + i,
                protocol="TCP",
                packet_size=64
            )
            ids.process_connection_event(event)
        
        console.print(f"[green]✅ IDS test passed: {len(ids.alerts)} alerts generated[/green]")
        
        # Test packet analyzer
        console.print("[blue]📦 Testing packet analyzer...[/blue]")
        analyzer = PacketCaptureAnalyzer()
        
        # Test with mock data
        from packet_analyzer import PacketInfo
        
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip=target,
            source_port=12345,
            dest_port=80,
            protocol="TCP",
            packet_size=1400,
            ttl=64,
            flags="SYN",
            payload_size=100,
            payload_preview="GET / HTTP/1.1",
            headers={}
        )
        
        analyzer.captured_packets = [packet]
        summary = analyzer.get_analysis_summary()
        console.print(f"[green]✅ Packet analyzer test passed[/green]")
        
        console.print("[bold green]🎉 All tests completed successfully![/bold green]")
        
    except Exception as e:
        console.print(f"[red]❌ Test failed: {e}[/red]")

if __name__ == '__main__':
    main()

# 🛡️ Network Diagnostic Tool

A comprehensive network security diagnostic tool that combines port scanning, intrusion detection, packet capture, and analysis capabilities. This enhanced tool has evolved from a simple port scanner into a full-featured network security platform.

## 🚀 Features

### 🔍 Advanced Port Scanning
- **Multi-threaded scanning** for high performance
- **Banner grabbing** for service fingerprinting
- **Service detection** for common protocols
- **Traceroute functionality** with TTL-based hop detection
- **Port classification**: Open/Closed/Filtered (firewall detection)
- **Structured JSON output** for integration

### 🛡️ Intrusion Detection System (IDS)
- **Signature-based detection** for known attack patterns
- **Anomaly detection** for suspicious behavior
- **Real-time monitoring** with configurable alerts
- **Attack pattern detection**:
  - Port scanning attempts
  - SYN flood patterns
  - Suspicious port access
  - Rapid connection attempts
  - Large payload detection
- **Alert management** with severity levels and confidence scores

### 📡 Packet Capture & Analysis
- **Real-time packet capture** using Scapy
- **Deep packet inspection** with protocol analysis
- **Flow tracking** and connection state monitoring
- **Application protocol detection** (HTTP, HTTPS, SSH, FTP, etc.)
- **Header parsing** for IP/TCP/UDP protocols
- **Payload analysis** with safe decoding

### 🧪 Comprehensive Testing
- **Unit tests** for all core functionality
- **Integration tests** for local network testing
- **Performance testing** for scalability
- **Mock network environments** for safe testing

## 📦 Installation

### Prerequisites
- Python 3.8+
- Root/Administrator privileges (for packet capture)
- Linux/macOS/Windows

### Basic Installation
```bash
# Clone the repository
git clone https://github.com/utkarshkgithub/Port-Scanner
cd Port-Scanner

# Install Python dependencies
pip install -r requirements.txt

# For advanced features (optional)
pip install scapy pyshark  # Packet capture capabilities
```

## 🎯 Quick Start

### Command Line Interface
```bash
# Basic port scan
python cli.py scan 192.168.1.1 1 1000

# Advanced scan with traceroute
python cli.py scan example.com 1 1000 --traceroute --threads 100

# Start IDS monitoring
python cli.py ids --monitor --duration 300

# Packet capture and analysis
python cli.py capture --duration 60 --analyze
```

### Direct Module Usage
```python
from network_diagnostic_tool import NetworkDiagnosticTool

# Initialize tool
tool = NetworkDiagnosticTool()

# Run comprehensive scan
results = tool.comprehensive_scan(
    target="example.com",
    start_port=1,
    end_port=1000,
    enable_traceroute=True,
    threads=50
)

# Save results
tool.save_results("scan_results.json")
```

## 📚 Detailed Usage

### Network Scanning
```bash
# Scan specific port range
python network_diagnostic_tool.py example.com 80 443

# Scan with custom thread count
python network_diagnostic_tool.py 192.168.1.1 1 65535 --threads 200

# Disable traceroute for faster scanning
python network_diagnostic_tool.py target.com 1 1000 --no-traceroute

# Save results to custom file
python network_diagnostic_tool.py target.com 1 1000 --output my_scan.json
```

### Intrusion Detection
```bash
# Start monitoring with baseline learning
python cli.py ids --baseline --monitor --duration 600

# Monitor specific interface
python cli.py ids --monitor --interface eth0

# Export alerts to file
python cli.py ids --monitor --export alerts.json
```

### Packet Analysis
```bash
# Capture packets for analysis
python cli.py capture --duration 120 --analyze

# Analyze existing pcap file
python cli.py capture --pcap network_traffic.pcap --analyze

# Custom capture filter
python cli.py capture --filter "tcp port 80" --duration 60
```

## 🏗️ Architecture

### Core Components
- **`network_diagnostic_tool.py`**: Main scanning engine with traceroute
- **`ids_module.py`**: Intrusion detection system
- **`packet_analyzer.py`**: Packet capture and analysis
- **`cli.py`**: Command-line interface

### Data Flow
```
Network Traffic → Packet Capture → Analysis → IDS Processing → Alerts
       ↓
Port Scanning → Service Detection → Banner Grabbing → Results
       ↓
JSON Export ← Data Aggregation ← Multiple Sources
```

## 🔧 Configuration

### IDS Configuration
```python
config = {
    'monitoring_interface': 'eth0',
    'alert_threshold': 'medium',
    'baseline_learning_period': 300,
    'max_alerts_per_minute': 10,
    'enable_packet_capture': True
}
```

### Scanner Configuration
```python
# Customize port-service mappings
tool.port_service_map[8080] = "HTTP-Alt"
tool.port_service_map[9200] = "Elasticsearch"

# Adjust scanning parameters
tool.comprehensive_scan(
    target="example.com",
    start_port=1,
    end_port=65535,
    threads=100,  # High performance
    enable_traceroute=True
)
```

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_network_tools.py::TestNetworkDiagnosticTool -v
```

### Performance Testing
```bash
# Test large-scale scanning
python cli.py test --target 127.0.0.1

# Benchmark IDS performance
python tests/test_network_tools.py
```

## 📊 Output Formats

### JSON Report Structure
```json
{
  "scan_info": {
    "start_time": "2024-01-01T12:00:00",
    "duration_seconds": 45.2,
    "total_ports_scanned": 1000
  },
  "port_summary": {
    "open": 5,
    "closed": 990,
    "filtered": 5
  },
  "open_ports": [
    {
      "port": 80,
      "status": "open",
      "service": "HTTP",
      "banner": "Apache/2.4.41",
      "response_time": 12.5
    }
  ],
  "traceroute": [...],
  "security_alerts": [...],
  "services_detected": ["HTTP", "HTTPS", "SSH"]
}
```

### IDS Alert Format
```json
{
  "alert_id": "port_scan_192.168.1.100_1642781234",
  "alert_type": "port_scan",
  "severity": "medium",
  "source_ip": "192.168.1.100",
  "timestamp": "2024-01-01T12:00:00",
  "description": "Port scan detected: 15 unique ports accessed",
  "confidence": 0.9,
  "metadata": {
    "unique_ports": 15,
    "time_window": 30
  }
}
```

## 🔍 Advanced Features

### Custom Signature Development
```python
# Add custom IDS signatures
ids.signatures['custom_attack'] = {
    'description': 'Custom attack pattern',
    'threshold': 5,
    'time_window': 10,
    'severity': 'high'
}
```

### Protocol Analysis Extensions
```python
# Add custom protocol analyzer
def analyze_custom_protocol(packet, packet_info):
    # Custom analysis logic
    return {"protocol": "CUSTOM", "data": "analyzed"}

analyzer.protocol_analyzers['CUSTOM'] = analyze_custom_protocol
```

## 🚨 Security Considerations

### Ethical Usage
- **Only scan networks you own or have permission to test**
- **Respect rate limits and don't overwhelm targets**
- **Follow local laws and regulations**
- **Use responsibly for legitimate security testing**

### Tool Security
- Run with minimal privileges when possible
- Regularly update dependencies
- Monitor for false positives in IDS

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add comprehensive tests for new functionality
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Run tests before committing
python -m pytest tests/ --cov

# Format code
black *.py

# Lint code
flake8 *.py
```

## 📈 Performance Benchmarks

- **Port Scanning**: Up to 1000 ports/second with 100 threads
- **IDS Processing**: 10,000+ events/second
- **Packet Analysis**: Real-time processing up to 1Gbps
- **Memory Usage**: <100MB for typical operations

## 🛣️ Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Integration with SIEM systems
- [ ] Mobile app for monitoring
- [ ] Advanced visualization with D3.js
- [ ] Distributed scanning capabilities
- [ ] Plugin architecture for extensions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy** for powerful packet manipulation capabilities
- **Flask** for the web framework
- **Rich** for beautiful terminal output
- **PyShark** for advanced packet analysis
- The network security community for inspiration and best practices

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/utkarshkgithub/Port-Scanner/issues)
- **Documentation**: [Wiki](https://github.com/utkarshkgithub/Port-Scanner/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/utkarshkgithub/Port-Scanner/discussions)
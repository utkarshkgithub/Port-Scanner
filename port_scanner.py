#!usr/bin/python3

"""
Legacy Port Scanner - Backward Compatibility
This is the original port scanner maintained for backward compatibility.
For advanced features, use network_diagnostic_tool.py or cli.py
"""

import socket
import sys
import time
import threading

print("-"*70)
print("Simple Port Scanner (Legacy Version)")
print("For advanced features, use: python cli.py scan")
print("-"*70)

usage = "python3 port_scanner.py TARGET START_PORT END_PORT"
start_time = time.time()

port_service_map = {
    80: "HTTP (Web server)",
    443: "HTTPS (Secure web server)",
    22: "SSH (Secure Shell)",
    21: "FTP (File Transfer Protocol)",
    25: "SMTP (Mail server)",
    3306: "MySQL (Database)",
    8080: "HTTP Alternate",
    53: "DNS (Domain Name System)",
    135: "MS RPC (Microsoft Remote Procedure Call)"
}

def get_service_name(port):
    return port_service_map.get(port, " ")

if(len(sys.argv)!=4):
  print(usage)
  print("\nFor advanced scanning features, try:")
  print("python cli.py scan TARGET START_PORT END_PORT")
  sys.exit()

try:
  target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
  print("Name resolution error")
  sys.exit()

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

print("Scanning Target",target)

def scan_port(port):
  # print("Scanning port:",port)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(2)
  conn = s.connect_ex((target, port))
  if(not conn):
    service = get_service_name(port)
    delimeter = "- Service - "
    if(service==" "):
      delimeter=""
    print("Port {} is open {} {}".format(port,delimeter,service))
  s.close()

threads = []

for port in range(start_port, end_port+1):

  thread = threading.Thread(target= scan_port,args = (port,))
  threads.append(thread)
  thread.start()

for thread in threads:
    thread.join()

end_time =time.time()

print("Time elapsed:",end_time-start_time, 's')
print("bye!!")

# Display upgrade message
print("\n" + "="*50)
print("🚀 UPGRADE AVAILABLE!")
print("This is the legacy version. For advanced features try:")
print("python cli.py scan {} {} {}".format(sys.argv[1], sys.argv[2], sys.argv[3]))
print("\nNew features include:")
print("• Banner grabbing and service detection")
print("• Traceroute and network path analysis") 
print("• Intrusion detection system")
print("• Packet capture and analysis")
print("• Web dashboard with real-time monitoring")
print("• JSON export and structured logging")
print("="*50)
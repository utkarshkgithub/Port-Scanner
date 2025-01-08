#!usr/bin/python3

import socket
import sys
import time
import threading

print("-"*70)
print("Simple Port Scanner")
print("-"*70)
usage = "python3 port_scan.py TARGET START_PORT END_PORT"
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
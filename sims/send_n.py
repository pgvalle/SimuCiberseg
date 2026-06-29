import socket
import sys
import time

from packet_utils import build_ethernet_header, build_ipv4_tcp

server_ip = sys.argv[1]
port = int(sys.argv[2])
n = int(sys.argv[3])
ip = "10.1.99.99"

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("h2-eth0", 0))

eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x0800)
payload = b"x" * 512
seq = 0

for i in range(n):
    ip_tcp_payload = build_ipv4_tcp(
        ip, server_ip, 50000, port, "S", seq, payload=payload
    )
    pkt = eth_hdr + ip_tcp_payload
    s.sendall(pkt)
    seq += 512
    time.sleep(0.001)

s.close()

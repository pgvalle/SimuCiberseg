import os
import socket
import sys
import time

from packet_utils import build_ethernet_header, build_ipv6_tcp

server_ip = sys.argv[1]
port = int(sys.argv[2])
n = int(sys.argv[3])
ip = "2001:db8:2::99"

os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:2::101/64 dev h2-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:1::/64 dev h2-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:1::101 lladdr 00:04:00:00:01:01 dev h2-eth0 2>/dev/null"
)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("h2-eth0", 0))

eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x86DD)
payload = b"x" * 512
seq = 0

for i in range(n):
    ip_tcp_payload = build_ipv6_tcp(
        ip, server_ip, 50000, port, "S", seq, payload=payload
    )
    pkt = eth_hdr + ip_tcp_payload
    s.sendall(pkt)
    seq += 512
    time.sleep(0.001)

s.close()

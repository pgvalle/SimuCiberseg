import os
import random
import socket
import sys
import threading
import time

from packet_utils import build_ethernet_header, build_ipv6_tcp

if len(sys.argv) < 5:
    print(
        "Usage: python send_mixed_traffic_v6.py <server_ip> <port> <num_flows> <attack_ratio>"
    )
    sys.exit(1)

server_ip = sys.argv[1]
port = int(sys.argv[2])
num_flows = int(sys.argv[3])
attack_ratio = float(sys.argv[4])

# Configure host IPv6 address and static neighbor
os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h1-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h1-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:1::101/64 dev h1-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:2::/64 dev h1-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:2::101 lladdr 00:04:00:00:02:01 dev h1-eth0 2>/dev/null"
)


num_attack = int(num_flows * attack_ratio)
num_legit = num_flows - num_attack

start_time = time.time()


def legitimate_flow(server_ip, port, num_legit):
    thread_sleep = max(0.05, num_legit / 1500.0)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("2001:db8:1::101", 0))
        s.connect((server_ip, port))
        while time.time() - start_time < 60.0:
            s.send(b"LEGITIMATE_PAYLOAD".ljust(1000, b"X"))
            time.sleep(thread_sleep)
        s.close()
    except Exception as e:
        print("Legit flow error: %s" % e)


attack_flows = []
for i in range(num_attack):
    attack_flows.append(
        {
            "src": "2001:db8:1::%d" % (200 + i),
            "sport": random.randint(10000, 65000),
            "seq": random.randint(1000, 90000),
        }
    )


def attacker_thread():
    s_raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s_raw.bind(("h1-eth0", 0))
    eth_hdr = build_ethernet_header("00:04:00:00:01:01", "00:04:00:00:02:01", 0x86DD)

    while time.time() - start_time < 60.0:
        for f in attack_flows:
            ipv6_tcp_payload = build_ipv6_tcp(
                f["src"],
                server_ip,
                f["sport"],
                port,
                "PA",
                f["seq"],
                ack=1,
                payload=b"ATTACK_PAYLOAD".ljust(1000, b"X"),
            )
            pkt = eth_hdr + ipv6_tcp_payload
            s_raw.send(pkt)
            f["seq"] += 1000
            time.sleep(max(0.001, 1.0 / 1500.0))


print(
    "Starting IPv6 Mixed Traffic: %d legit flows, %d attack flows"
    % (num_legit, num_attack)
)

threads = []
for _ in range(num_legit):
    t = threading.Thread(target=legitimate_flow, args=(server_ip, port, num_legit))
    t.daemon = True
    t.start()
    threads.append(t)
    time.sleep(0.01)

if num_attack > 0:
    t = threading.Thread(target=attacker_thread)
    t.daemon = True
    t.start()
    threads.append(t)

time.sleep(65.0)

print("Traffic generation finished.")

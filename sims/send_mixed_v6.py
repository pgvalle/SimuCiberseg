import os
import socket
import sys
import threading
import time

from config import (
    ATTACK_END,
    ATTACK_START,
    NUM_FLOWS,
    PAYLOAD_SIZE,
    RECV_PORT,
    SIMULATION_END,
)
from packet_utils import build_ethernet_header, build_ipv6_tcp

recv_ip = sys.argv[1]
attack_ratio = float(sys.argv[2])
start_time = time.time()

os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:2::101/64 dev h2-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:1::/64 dev h2-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:1::101 lladdr 00:04:00:00:01:01 dev h2-eth0 2>/dev/null"
)


def legit_flow():
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect((recv_ip, RECV_PORT))

        payload = b"." * PAYLOAD_SIZE
        while time.time() - start_time < SIMULATION_END:
            sock.sendall(payload)
            time.sleep(0.05)
    except socket.error as e:
        print("Thread encountered an error: %s" % e)
    finally:
        if sock is not None:
            sock.close()


def attack_flow(props):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("h2-eth0", 0))

    eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x86DD)
    payload = b"x" * PAYLOAD_SIZE

    while time.time() - start_time < ATTACK_START:
        time.sleep(1.0)

    while time.time() - start_time < ATTACK_END:
        ip_tcp_payload = build_ipv6_tcp(
            props["src_ip"],
            recv_ip,
            props["sport"],
            RECV_PORT,
            "PA",
            props["seq"],
            ack=1,
            payload=payload,
        )
        pkt = eth_hdr + ip_tcp_payload
        sock.send(pkt)
        props["seq"] += PAYLOAD_SIZE
        time.sleep(0.05)

    sock.close()


for i in range(NUM_FLOWS):
    is_attack = (i + 1) / NUM_FLOWS < attack_ratio
    if is_attack:
        src_ip = "2001:db9:2::%x" % (0x1000 + i)
        props = {"src_ip": src_ip, "sport": 10000 + i, "seq": 0}
        thread = threading.Thread(target=attack_flow, args=(props,))
        thread.daemon = True
        thread.start()
    else:
        thread = threading.Thread(target=legit_flow)
        thread.daemon = True
        thread.start()

while time.time() - start_time < SIMULATION_END + 5.0:
    time.sleep(1.0)

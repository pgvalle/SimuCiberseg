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
from packet_utils import build_ethernet_header, build_ipv4_tcp

recv_ip = sys.argv[1]
attack_ratio = float(sys.argv[2])
start_time = time.time()


def legit_flow():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((recv_ip, RECV_PORT))

        payload = b"." * PAYLOAD_SIZE
        while time.time() - start_time < SIMULATION_END:
            sock.sendall(payload)
            time.sleep(0.05)
    except socket.error as e:
        print("Thread encountered an error: %s" % e)
    finally:
        sock.close()


def attack_flow(props):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("h2-eth0", 0))

    eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x0800)
    payload = b"x" * PAYLOAD_SIZE

    while time.time() - start_time < ATTACK_START:
        time.sleep(1.0)

    while time.time() - start_time < ATTACK_END:
        ip_tcp_payload = build_ipv4_tcp(
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
        props = {
            "src_ip": "10.1.0.%d" % (i + 1),
            "sport": 10000 + i,
            "seq": 0,
        }
        thread = threading.Thread(target=attack_flow, args=(props,))
        thread.daemon = True
        thread.start()
    else:
        thread = threading.Thread(target=legit_flow)
        thread.daemon = True
        thread.start()

while time.time() - start_time < SIMULATION_END + 5.0:
    time.sleep(1.0)

import random
import socket
import sys
import threading
import time

from packet_utils import build_ethernet_header, build_ipv4_tcp

server_ip = sys.argv[1]
port = int(sys.argv[2])
num_flows = int(sys.argv[3])
attack_ratio = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
start_time = time.time()


def legit_flow():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, port))

        payload = b"." * 512
        while time.time() - start_time < 60:
            sock.sendall(payload)
            time.sleep(0.05)
    except socket.error as e:
        print("Thread encountered an error: %s" % e)
    finally:
        sock.close()


def attack_flow():
    src_ip = "10.1.%d.%d" % (random.randint(0, 255), random.randint(0, 254))
    props = {"src_ip": src_ip, "sport": 10000 + i, "seq": 512}

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("h2-eth0", 0))

    eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x0800)
    payload = b"x" * 512

    while time.time() - start_time < 20.0:
        time.sleep(1.0)

    while time.time() - start_time < 40.0:
        ip_tcp_payload = build_ipv4_tcp(
            props["src_ip"],
            server_ip,
            props["sport"],
            port,
            "PA",
            props["seq"],
            ack=1,
            payload=payload,
        )
        pkt = eth_hdr + ip_tcp_payload
        sock.send(pkt)
        props["seq"] += 512
        time.sleep(0.05)

    sock.close()


for i in range(num_flows):
    is_attack = (i + 1) / num_flows < attack_ratio
    if is_attack:
        thread = threading.Thread(target=attack_flow)
        thread.daemon = True
        thread.start()
    else:
        thread = threading.Thread(target=legit_flow)
        thread.daemon = True
        thread.start()

while time.time() - start_time < 65.0:
    time.sleep(1.0)

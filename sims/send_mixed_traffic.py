import sys
import time
import random
import socket
import threading
from packet_utils import build_ipv4_tcp, build_ethernet_header

server_ip = sys.argv[1]
port = int(sys.argv[2])
num_flows = int(sys.argv[3])
attack_ratio = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5

start_time = time.time()

def legitimate_flow(server_ip, port, num_legit):
    thread_sleep = max(0.05, num_legit / 1500.0)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("10.0.1.101", 0))
        s.connect((server_ip, port))
        while time.time() - start_time < 60.0:
            s.send(b"LEGITIMATE_PAYLOAD")
            time.sleep(thread_sleep)
        s.close()
    except Exception:
        pass

attack_flows = []
for i in range(num_flows):
    is_attack = random.random() < attack_ratio
    if is_attack:
        src_ip = "10.1.%d.%d" % (random.randint(0,255), random.randint(0,255))
        attack_flows.append({
            'src_ip': src_ip,
            'sport': 10000 + i,
            'seq': 1000
        })
    else:
        t = threading.Thread(target=legitimate_flow, args=(server_ip, port, num_flows * (1 - attack_ratio)))
        t.daemon = True
        t.start()

if not attack_flows:
    while time.time() - start_time < 60.0:
        time.sleep(1)
    sys.exit(0)

s_raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s_raw.bind(("h1-eth0", 0))

eth_hdr = build_ethernet_header("00:04:00:00:01:01", "00:04:00:00:02:01", 0x0800)

while time.time() - start_time < 60.0:
    f = random.choice(attack_flows)
    ip_tcp_payload = build_ipv4_tcp(f['src_ip'], server_ip, f['sport'], port, "PA", f['seq'], ack=1, payload=b"ATTACK_PAYLOAD")
    pkt = eth_hdr + ip_tcp_payload
    s_raw.send(pkt)
    f['seq'] += 1
    time.sleep(max(0.001, 1.0 / 1500.0))

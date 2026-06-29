import socket
import sys
import time

from config import PAYLOAD_SIZE, RECV_PORT, SIMULATION_END

recv_ip = sys.argv[1]
start_time = time.time()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 0))
sock.connect((recv_ip, RECV_PORT))
payload = b"." * PAYLOAD_SIZE

while time.time() - start_time < SIMULATION_END:
    sock.sendall(payload)
    time.sleep(0.001)

time.sleep(5)
sock.close()

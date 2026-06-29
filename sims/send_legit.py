import socket
import sys
import time

server_ip = sys.argv[1]
port = int(sys.argv[2])
start_time = time.time()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 0))
sock.connect((server_ip, port))
payload = b"." * 512

while time.time() - start_time < 60.0:
    sock.sendall(payload)
    time.sleep(0.05)

time.sleep(5)
sock.close()

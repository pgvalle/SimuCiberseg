import os
import socket
import sys
import time

server_ip = sys.argv[1]
port = int(sys.argv[2])
start_time = time.time()

os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h2-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:2::101/64 dev h2-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:1::/64 dev h2-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:1::101 lladdr 00:04:00:00:01:01 dev h2-eth0 2>/dev/null"
)

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.bind(("::", 0))
sock.connect((server_ip, port))
payload = b"." * 512

while time.time() - start_time < 60.0:
    sock.sendall(payload)
    time.sleep(0.05)

time.sleep(5)
sock.close()

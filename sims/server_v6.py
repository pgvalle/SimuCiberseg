import os
import socket
import sys
import threading
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
start_time = time.time()

# Configure host IPv6 address and static neighbor
os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h1-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h1-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:1::101/64 dev h1-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:2::/64 dev h1-eth0 2>/dev/null")

# FIXED: Replaced 01:01 with 02:01 (the Client's MAC address)
os.system(
    "ip -6 neigh add 2001:db8:2::101 lladdr 00:04:00:00:02:01 dev h1-eth0 2>/dev/null"
)


def handle_client(conn, addr):
    conn.settimeout(2.0)
    # IPv6 address is a 4-tuple (host, port, flowinfo, scopeid)
    ip, sport = addr[:2]
    while True:
        try:
            conn.recv(1024)
            rel_time = time.time() - start_time
            print("%.3f - SERVER_RECEIVED: %s:%d" % (rel_time, ip, sport))
        except socket.timeout:
            continue
        except:
            break
    conn.close()


def start_server():
    # Use AF_INET6 for IPv6
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind(("::", port))
    s.listen(200)
    print("0.000 - SERVER_START listening on port %d..." % port)

    while True:
        try:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            break
        except KeyboardInterrupt:
            break

    s.close()
    print("%.3f - SERVER_SHUTDOWN" % (time.time() - start_time))


if __name__ == "__main__":
    start_server()

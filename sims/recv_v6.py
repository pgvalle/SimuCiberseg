import os
import socket
import sys
import threading
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
start_time = time.time()

os.system("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h1-eth0/disable_ipv6 2>/dev/null")
os.system("echo 0 > /proc/sys/net/ipv6/conf/h1-eth0/accept_dad 2>/dev/null")
os.system("ip -6 addr add 2001:db8:1::101/64 dev h1-eth0 2>/dev/null")
os.system("ip -6 route add 2001:db8:2::/64 dev h1-eth0 2>/dev/null")
os.system(
    "ip -6 neigh add 2001:db8:2::101 lladdr 00:04:00:00:02:01 dev h1-eth0 2>/dev/null"
)


def handle_conn(conn, addr):
    ip, sport = addr[:2]
    print("Accepted connection from %s:%s" % addr)
    try:
        while True:
            data = conn.recv(512)
            if len(data) == 0:
                break
            rel_time = time.time() - start_time
            print("Received at %.3f from %s:%d" % (rel_time, ip, sport))
    except socket.error as e:
        print("Socket error with %s:%s %s" % (ip, sport, e))
    finally:
        conn.close()
        print("Connection closed with %s:%s" % addr)


def listen():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("::", port))
    sock.listen(200)
    print("Listening on port %d..." % port)

    try:
        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(target=handle_conn, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("Shutdown at %.3fs" % (time.time() - start_time))
    finally:
        sock.close()


if __name__ == "__main__":
    listen()

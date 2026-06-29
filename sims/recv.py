import socket
import sys
import threading
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
start_time = time.time()


def handle_conn(conn, addr):
    ip, sport = addr
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
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

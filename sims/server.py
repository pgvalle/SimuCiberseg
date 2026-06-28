import socket
import sys
import threading
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
start_time = time.time()


def handle_client(conn, addr):
    ip, sport = addr
    while True:
        try:
            conn.recv(512)
            rel_time = time.time() - start_time
            print("%.3f - SERVER_RECEIVED: %s:%d" % (rel_time, ip, sport))
        except:
            break
    conn.close()


def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
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

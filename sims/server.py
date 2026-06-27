import socket
import sys
import threading
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

start_time = time.time()


def handle_client(conn, addr):
    conn.settimeout(2.0)
    ip, sport = addr
    while time.time() - start_time < 120:
        try:
            data = conn.recv(1024)
            if not data:
                break
            rel_time = time.time() - start_time
            print("%.3f - SERVER_RECEIVED: %s:%d" % (rel_time, ip, sport))
        except socket.timeout:
            continue
        except:
            break
    conn.close()


def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(200)
    print("0.000 - SERVER_START listening on port %d..." % port)

    s.settimeout(0.5)

    while time.time() - start_time < 120:
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

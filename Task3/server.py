import socket
import argparse
import time

def run_server(nagle, delay_ack):
    # Configure socket before binding
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, not nagle)
    
    if not delay_ack:
        try:  # Linux-specific option
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except AttributeError:
            print("WARNING: TCP_QUICKACK not supported")

    sock.bind(('0.0.0.0', 5201))
    sock.listen(1)
    print("SERVER: Listening on port 5201")

    try:
        conn, addr = sock.accept()
        print(f"SERVER: Connection from {addr[0]}")
    except KeyboardInterrupt:
        sock.close()
        return

    start_time = time.time()
    total_bytes = 0
    
    try:
        while time.time() - start_time < 125:  # 120s + buffer
            data = conn.recv(4096)
            if not data:
                break
            total_bytes += len(data)
    finally:
        conn.close()
        sock.close()
        duration = time.time() - start_time
        print(f"SERVER: Received {total_bytes} bytes in {duration:.2f}s")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--nagle', type=int, choices=[0,1], default=1)
    parser.add_argument('--delay_ack', type=int, choices=[0,1], default=1)
    args = parser.parse_args()
    run_server(args.nagle, args.delay_ack)
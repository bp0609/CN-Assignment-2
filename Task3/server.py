import socket
import argparse

def receive_file(port, disable_nagle):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if disable_nagle:
        # Disable Nagle's algorithm on server side if needed.
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind(('', port))
    s.listen(1)
    print(f"Server listening on port {port}")
    
    conn, addr = s.accept()
    print(f"Connected by {addr}")
    data_received = b''
    while True:
        data = conn.recv(1024)
        if not data:
            break
        data_received += data
    print(f"Received {len(data_received)} bytes.")
    conn.close()
    s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--disable_nagle', action='store_true', help='Disable Nagle’s algorithm')
    args = parser.parse_args()
    receive_file(args.port, args.disable_nagle)

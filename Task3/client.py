import socket
import time
import argparse

def send_file(host, port, filename, disable_nagle):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if disable_nagle:
        # Disable Nagle's algorithm
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((host, port))
    
    with open(filename, 'rb') as f:
        file_data = f.read()
    
    # Send data at 40 bytes per second over 2 minutes (~120 seconds)
    chunk_size = 40
    total_sent = 0
    start_time = time.time()
    while total_sent < len(file_data):
        end = min(total_sent + chunk_size, len(file_data))
        s.sendall(file_data[total_sent:end])
        total_sent = end
        time.sleep(1)  # sending 40 bytes per second
    s.close()
    elapsed = time.time() - start_time
    print(f"Finished sending {len(file_data)} bytes in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost', help='Server IP or hostname')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--file', default='4kb_file.bin', help='File to send')
    parser.add_argument('--disable_nagle', action='store_true', help='Disable Nagle’s algorithm')
    args = parser.parse_args()
    send_file(args.host, args.port, args.file, args.disable_nagle)

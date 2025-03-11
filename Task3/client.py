import socket
import time
import argparse
import sys

def run_client(nagle, delay_ack):
    # Configure socket before connecting
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, not nagle)
    
    if not delay_ack:
        try:  # Linux-specific option
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except AttributeError:
            print("WARNING: TCP_QUICKACK not supported", file=sys.stderr)

    # Connection setup with retries
    connected = False
    for _ in range(5):
        try:
            sock.connect(('10.0.0.7', 5201))
            connected = True
            break
        except ConnectionRefusedError:
            print("Connection refused, retrying...", file=sys.stderr)
            time.sleep(2)
    
    if not connected:
        print("FATAL: Connection failed after 5 attempts", file=sys.stderr)
        sys.exit(1)

    # Transmission loop with precise timing
    data = b'X' * 40  # 40-byte payload
    start_time = time.time()
    end_time = start_time + 120  # Strict 2-minute deadline
    
    try:
        while time.time() < end_time:
            sock.sendall(data)
            # Maintain exact 1-second intervals
            elapsed = time.time() - start_time
            sleep_time = (1 - (elapsed % 1)) if (elapsed % 1) < 0.95 else 0
            time.sleep(max(0, sleep_time))
    except Exception as e:
        print(f"Transmission error: {str(e)}", file=sys.stderr)
    finally:
        sock.close()
        duration = time.time() - start_time
        print(f"CLIENT: Transmitted {40*int(duration)} bytes in {duration:.2f}s")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--nagle', type=int, choices=[0,1], default=1)
    parser.add_argument('--delay_ack', type=int, choices=[0,1], default=1)
    args = parser.parse_args()
    run_client(args.nagle, args.delay_ack)
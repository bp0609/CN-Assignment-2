#!/usr/bin/env python3
import os
import dpkt

def analyze(pcap, config):
    print(f"\n===== Analysis: {config} =====")
    
    # Validate pcap file
    if not os.path.isfile(pcap):
        print(f"ERROR: File {pcap} not found!")
        return
    
    # Open and read pcap file
    try:
        with open(pcap, 'rb') as f:
            pcap_reader = dpkt.pcap.Reader(f)
            packets = list(pcap_reader)
    except Exception as e:
        print("Error reading pcap file:", e)
        return

    if not packets:
        print("No packets found in pcap.")
        return

    # Compute capture duration from packet timestamps
    timestamps = [ts for ts, _ in packets]
    first_ts = min(timestamps)
    last_ts = max(timestamps)
    duration = last_ts - first_ts
    print(f"Capture duration: {duration:.2f} seconds")
    if duration < 100:
        print(f"WARNING: Short capture duration ({duration:.2f} seconds)")
    
    total_bits_throughput = 0.0
    total_bits_goodput = 0.0
    total_packets = 0
    lost_packets = 0
    max_payload = 0
    max_frame = 0

    # For retransmission detection, maintain a set keyed by (src, dst, sport, dport, seq)
    seen_keys = set()

    # Process each packet in the pcap file
    for ts, buf in packets:
        frame_len = len(buf)
        # Parse the Ethernet frame; skip malformed frames
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            continue
        
        # Only process IP packets carrying TCP
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        
        try:
            tcp = ip.data
        except Exception:
            continue
        
        # Filter: only TCP packets with destination port 5201 and non-zero TCP payload
        if tcp.dport != 5201:
            continue
        payload_len = len(tcp.data)
        if payload_len <= 0:
            continue
        
        total_packets += 1
        total_bits_throughput += frame_len * 8  # frame bits for throughput
        
        if frame_len > max_frame:
            max_frame = frame_len
        if payload_len > max_payload:
            max_payload = payload_len
        
        # Use (src, dst, sport, dport, seq) as a key to detect retransmissions.
        # Note: This is a simple heuristic and may not catch all retransmissions.
        key = (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq)
        if key in seen_keys:
            lost_packets += 1
        else:
            seen_keys.add(key)
            total_bits_goodput += payload_len * 8  # only count non-retransmitted payload bits

    throughput = total_bits_throughput / (duration * 1e6) if duration > 0 else 0.0
    goodput = total_bits_goodput / 1e6
    # Loss rate computed similar to the original script, with +1 in denominator to avoid div-by-zero.
    loss_rate = (lost_packets * 100) / (total_packets + 1)

    print(f"Throughput: {throughput:.8f} Mbps")
    print(f"Goodput: {goodput:.8f} Mbps")
    print(f"Packet Loss Rate: {loss_rate:.2f}%")
    print(f"Max TCP Payload: {max_payload} bytes")
    print(f"Max Frame Size: {max_frame} bytes")

def main():
    analyze("task3_1.pcap", "Nagle ON, Delayed-ACK ON")
    analyze("task3_2.pcap", "Nagle ON, Delayed-ACK OFF")
    analyze("task3_3.pcap", "Nagle OFF, Delayed-ACK ON")
    analyze("task3_4.pcap", "Nagle OFF, Delayed-ACK OFF")

if __name__ == '__main__':
    main()

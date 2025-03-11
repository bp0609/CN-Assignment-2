import dpkt
import datetime
import matplotlib.pyplot as plt
import numpy as np
import os
from tqdm import tqdm

def process_capture(file_path, plot_dir, result_dir):
    try:
        with open(file_path, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            time_data = []
            size_data = []
            payload_data = []
            payload_times = []
            connection_map = {}
            window_data = []
            sequence_map = {}
            peak_window = 0
            bin_duration = 0.2
            initial_time = None

            for timestamp, buffer in capture:
                if initial_time is None:
                    initial_time = datetime.datetime.utcfromtimestamp(timestamp)
                delta = datetime.datetime.utcfromtimestamp(timestamp) - initial_time
                seconds_offset = delta.total_seconds()
                
                frame = dpkt.ethernet.Ethernet(buffer)
                if isinstance(frame.data, dpkt.ip.IP):
                    ip_packet = frame.data
                    flow_key = (ip_packet.src, ip_packet.dst)
                    if flow_key not in sequence_map:
                        sequence_map[flow_key] = set()
                    
                    if isinstance(ip_packet.data, dpkt.tcp.TCP):
                        tcp_segment = ip_packet.data
                        time_data.append(seconds_offset)
                        size_data.append(len(buffer))
                        window_data.append(tcp_segment.win)
                        peak_window = max(peak_window, tcp_segment.win)
                        
                        if tcp_segment.seq not in sequence_map[flow_key]:
                            payload_data.append(len(tcp_segment.data))
                            payload_times.append(seconds_offset)
                            sequence_map[flow_key].add(tcp_segment.seq)
                        else:
                            payload_data.append(0)
                            payload_times.append(seconds_offset)
                    else:
                        size_data.append(len(buffer))
                        payload_data.append(0)
                        payload_times.append(seconds_offset)
                else:
                    size_data.append(len(buffer))
                    payload_data.append(0)
                    payload_times.append(seconds_offset)

            if not time_data:
                return [], []

            start = time_data[0]
            end = time_data[-1]
            duration = end - start

            if duration == 0:
                return [], []

            bin_count = int(duration / bin_duration) + 1
            thru_times = []
            thru_values = []

            for idx in range(bin_count):
                bin_start = idx * bin_duration
                bin_end = bin_start + bin_duration
                window_bits = [s*8 for t, s in zip(time_data, size_data) if bin_start <= t <= bin_end]
                
                if window_bits:
                    rate = sum(window_bits) / bin_duration
                    thru_times.append(bin_start + bin_duration/2)
                    thru_values.append(rate)

            if not payload_times:
                return [], []

            start_p = payload_times[0]
            end_p = payload_times[-1]
            duration_p = end_p - start_p

            if duration_p == 0:
                return [], []

            bin_count_p = int(duration_p / bin_duration) + 1
            good_times = []
            good_values = []

            for idx in range(bin_count_p):
                bin_start = idx * bin_duration
                bin_end = bin_start + bin_duration
                valid_bits = [s*8 for t, s in zip(payload_times, payload_data) if bin_start <= t <= bin_end]
                
                if valid_bits:
                    rate = sum(valid_bits) / bin_duration
                    good_times.append(bin_start + bin_duration/2)
                    good_values.append(rate)

            total_thru = sum(size_data)*8/(time_data[-1]-time_data[0]) if time_data else 0
            total_good = sum(payload_data)*8/(time_data[-1]-time_data[0]) if time_data else 0

            unique_packets = sum(len(v) for v in sequence_map.values())
            total_packets = len(time_data)
            loss_ratio = (total_packets - unique_packets)/total_packets if total_packets else 0

            create_visualization(thru_times, thru_values, "Throughput (bits/s)", os.path.basename(file_path), plot_dir)
            create_visualization(good_times, good_values, "Goodput (bits/s)", os.path.basename(file_path), plot_dir)
            store_metrics(total_thru, total_good, loss_ratio, peak_window, os.path.basename(file_path), result_dir)
            create_visualization(time_data, window_data, "TCP Window Size", os.path.basename(file_path), plot_dir)

    except Exception as err:
        print(f"Processing error: {err}")

def create_visualization(x_vals, y_vals, graph_title, filename, output_path):
    if not x_vals:
        return

    plt.figure(figsize=(10,6))
    plt.plot(x_vals, y_vals)
    plt.xlabel("Time (seconds)")
    plt.ylabel(graph_title)
    plt.title(graph_title)
    plt.grid(True)
    plt.tight_layout()

    graph_name = os.path.splitext(filename)[0] + f"_{graph_title.replace(' ','_')}.png"
    plt.savefig(os.path.join(output_path, graph_name), dpi=300)
    plt.close()

def store_metrics(thru, good, loss, max_win, filename, output_path):
    metrics_file = os.path.splitext(filename)[0] + ".txt"
    full_path = os.path.join(output_path, metrics_file)
    with open(full_path, 'w') as f:
        f.write(f"Total Throughput: {thru:.2f} bits/s\n")
        f.write(f"Total Goodput: {good:.2f} bits/s\n")
        f.write(f"Packet Loss Rate: {loss:.2%}\n")
        f.write(f"Maximum Window Size: {max_win}\n")

if __name__ == "__main__":
    input_folder = "results/experiment_a/cc_vegas"
    graph_folder = "plots"
    metrics_folder = "plots"

    os.makedirs(graph_folder, exist_ok=True)
    os.makedirs(metrics_folder, exist_ok=True)

    capture_files = [os.path.join(input_folder, f) for f in os.listdir(input_folder) if f.endswith(".pcap")]
    for cap_file in tqdm(capture_files, desc="Analyzing captures"):
        process_capture(cap_file, graph_folder, metrics_folder)
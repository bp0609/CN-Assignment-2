import dpkt
import matplotlib.pyplot as plt
import os
from collections import defaultdict
from tqdm import tqdm

capture_file = "syn_mitigation.pcap"
# capture_file = "syn_mitigation.pcap"
graph_directory = "traffic_analysis"
os.makedirs(graph_directory, exist_ok=True)
time_resolution = 0.1

with open(capture_file, 'rb') as data_stream:
    packet_reader = dpkt.pcap.Reader(data_stream)
    relative_times = []
    packet_lengths = []
    base_time = None
    
    for timestamp, packet_data in tqdm(packet_reader, desc="Analyzing network data"):
        if base_time is None:
            base_time = timestamp
        relative_times.append(timestamp - base_time)
        packet_lengths.append(len(packet_data))

    time_slots = defaultdict(int)
    for event_time, data_size in zip(relative_times, packet_lengths):
        time_index = int(event_time / time_resolution)
        time_slots[time_index] += data_size

    sorted_intervals = sorted(time_slots.keys())
    traffic_data = [time_slots[interval] for interval in sorted_intervals]
    graph_timepoints = [idx * time_resolution for idx in sorted_intervals]

    plt.figure(figsize=(12, 6))
    plt.plot(graph_timepoints, traffic_data)
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Data Volume per Interval (bytes)")
    plt.title("Network Traffic Analysis")
    plt.grid(True)

    output_name = os.path.splitext(os.path.basename(capture_file))[0] + "_traffic_analysis.png"
    plt.savefig(os.path.join(graph_directory, output_name), dpi=300)
    plt.close()
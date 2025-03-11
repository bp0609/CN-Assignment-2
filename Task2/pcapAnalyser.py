import dpkt # I am using dpkt to read the pcap file
import datetime
import matplotlib.pyplot as plt
import os
from collections import defaultdict
from tqdm import tqdm

def plot_connection_durations(start_times, durations, attack_start_time, attack_end_time, filename, output_dir):
    if not start_times: 
        print(f"No connection data to plot for {filename}")
        return

    plt.figure(figsize=(12, 6))
    plt.scatter(start_times, durations, s=1)
    plt.xlabel("Connection Start Time (seconds)")
    plt.ylabel("Connection Duration (seconds)")
    plt.title("TCP Connection Durations")
    plt.grid(True)

    plt.axvline(x=attack_start_time, color='red', linestyle='--', label='Attack Start')
    plt.axvline(x=attack_end_time, color='green', linestyle='--', label='Attack End')
    plt.legend()

    plot_filename = os.path.splitext(filename)[0] + "_connection_durations.png"
    plt.savefig(os.path.join(output_dir, plot_filename), dpi=300)
    plt.close()

pcap_file = "Q2_attack_copy.pcap" # I changed the name of the pcap file to Q2_attack.pcap in order to plot the graph for the attack.
attack_start_time = 20.0  # Attack start time
attack_end_time = 120.0   # Attack end time
output_dir_plots = "connection_duration_plots" # This was the output directory for the plots

os.makedirs(output_dir_plots, exist_ok=True) # Create output directory if it doesn't exist
connections = defaultdict(lambda: {'start_time': None, 'end_time': None}) # This will store the connection data

with open(pcap_file, 'rb') as f: # We will first read the pcap file in binary mode
    pcap = dpkt.pcap.Reader(f) # We will use dpkt to read the pcap file
    first_packet_time = None 

    for ts, buf in tqdm(pcap, desc="Processing packets"):  # We will iterate over the packets in the pcap file
        eth = dpkt.ethernet.Ethernet(buf) # We will read the ethernet frame
        if isinstance(eth.data, dpkt.ip.IP): # We will check if the packet is an IP packet
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP): # We will check if the IP packet is a TCP packet
                tcp = ip.data
                connection_id = (ip.src, ip.dst, tcp.sport, tcp.dport) # This is the 4-tuple that uniquely identifies a connection

                if first_packet_time is None: # We will store the time of the first packet
                    first_packet_time = datetime.datetime.utcfromtimestamp(ts) # We will convert the timestamp to a datetime object

                packet_time = datetime.datetime.utcfromtimestamp(ts) # We will convert the timestamp to a datetime object

                if tcp.flags & dpkt.tcp.TH_SYN: # We will check if the packet is a SYN packet
                    if connections[connection_id]['start_time'] is None:
                        connections[connection_id]['start_time'] = packet_time

                if tcp.flags & dpkt.tcp.TH_FIN and tcp.flags & dpkt.tcp.TH_ACK: # We will check if the packet is a FIN-ACK packet
                    connections[connection_id]['fin_ack_time'] = packet_time

                if tcp.flags & dpkt.tcp.TH_RST: # We will check if the packet is a RST packet
                    connections[connection_id]['end_time'] = packet_time

                if tcp.flags & dpkt.tcp.TH_ACK and 'fin_ack_time' in connections[connection_id]: # We will check if the packet is an ACK packet that acknowledges the FIN-ACK
                    if packet_time > connections[connection_id]['fin_ack_time']:
                        connections[connection_id]['end_time'] = packet_time

    connection_durations = []
    connection_start_times = []

    for connection_id, connection_data in connections.items(): # We will iterate over the connections
        if connection_data['start_time'] is None:
            continue
        start_time = connection_data['start_time'] # We will get the start time of the connection
        end_time = connection_data.get('end_time') # We will get the end time of the connection

        if end_time: # We will calculate the duration of the connection
            duration = (end_time - start_time).total_seconds()
        else:
            duration = 100.0 # If the connection is not closed, we will assume a default duration of 100 seconds

        connection_durations.append(duration) # We will store the duration of the connection
        connection_start_times.append((start_time - first_packet_time).total_seconds()) # We will store the start time of the connection
    # We will plot the connection durations and save the plot
    plot_connection_durations(connection_start_times, connection_durations, attack_start_time, attack_end_time, os.path.basename(pcap_file), output_dir_plots)

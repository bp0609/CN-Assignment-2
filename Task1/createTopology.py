#!/usr/bin/python

import argparse
import os
import sys
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

def create_dir(path):
    """Create a directory if it does not exist."""
    if not os.path.exists(path):
        os.makedirs(path)

def store_tcp_info(host, filename):
    """Run 'ss -ti' on the host and store the output in the given file."""
    output = host.cmd("ss -ti")
    with open(filename, "w") as f:
        f.write(output)

def run_iperf_server(host, port=5201, logfile=""):
    info("Starting iperf3 server on %s\n" % host.name)
    if logfile:
        host.cmd("iperf3 -s -p %d --one-off > %s 2>&1 &" % (port, logfile))
    else:
        host.cmd("iperf3 -s -p %d --one-off &" % port)

def run_iperf_client(host, server_ip, port=5201, duration=150, cc="reno", parallel=10, logfile=""):
    """Run an iperf3 client on host to connect to server_ip, storing output in logfile if provided."""
    cmd = "iperf3 -c %s -p %d -b 15M -P 10 -t %d -C %s" % (server_ip, port, duration, cc)
    if logfile:
        cmd += " > %s 2>&1" % logfile
    info("Starting iperf3 client on %s:\n  %s\n" % (host.name, cmd))
    return host.cmd(cmd)


class CongestionTopo(Topo):
    def build(self, bw_config=False, loss_rate=0):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')

        self.addLink(h1, s1, cls=TCLink)
        self.addLink(h2, s1, cls=TCLink)
        self.addLink(h3, s2, cls=TCLink)
        self.addLink(h4, s3, cls=TCLink)
        self.addLink(h5, s3, cls=TCLink)
        self.addLink(h6, s4, cls=TCLink)
        self.addLink(h7, s4, cls=TCLink)

        # Create switch-switch links.
        if bw_config:
            # For experiment (c), configure bandwidth and loss on the chain links.
            self.addLink(s1, s2, cls=TCLink, bw=100)       # 100Mbps
            self.addLink(s2, s3, cls=TCLink, bw=50, loss=loss_rate)  # 50Mbps with loss
            self.addLink(s3, s4, cls=TCLink, bw=100)       # 100Mbps
            # Extra links used only in experiment (c)
            self.addLink(s2, s4, cls=TCLink)
            self.addLink(s1, s4, cls=TCLink)
        else:
            # For experiments (a) and (b): only the chain links.
            self.addLink(s1, s2, cls=TCLink)
            self.addLink(s2, s3, cls=TCLink)
            self.addLink(s3, s4, cls=TCLink)



def experiment_a(net, cc):

    info("\n***** Running Experiment (a) *****\n")
    result_dir = "results/experiment_a/cc_%s" % cc
    create_dir(result_dir)
    
    h1 = net.get('h1')
    h7 = net.get('h7')
    # set_tcp_cc(h1, cc)
    # set_tcp_cc(h7, cc)
    
    server_log = os.path.join(result_dir, "h7_server.log")
    client_log = os.path.join(result_dir, "h1_client.log")
    pcap_h1_log = os.path.join(result_dir, "h1.pcap")
    pcap_h7_log = os.path.join(result_dir, "h7.pcap")
    
    h7.cmd("tcpdump -i h7-eth0 -w %s &" % pcap_h7_log)
    h7.cmd(f"iperf3 -s -p 5201 > {server_log} 2>&1 &")
    # run_iperf_server(h7, logfile=server_log)
    time.sleep(2)
    
    print("Here")
    info("Starting iperf client on h1...\n")
    run_iperf_client(h1, h7.IP(), duration=150, cc=cc, logfile=client_log)
    print("Here1")
    info("Client finished. Waiting 5 seconds...\n")
    time.sleep(5)
    # Terminate iperf server process
    h7.cmd('pkill -f "tcpdump -i h7-eth0"')
    h7.cmd("pkill -f iperf3")

    info("Experiment (a) completed. Results stored in %s\n" % result_dir)

def experiment_b(net, cc):
    """
    Experiment (b): Staggered flows.
      - h1 runs for 150s (starting at T=0), h3 for 120s (starting at T=15),
        and h4 for 90s (starting at T=30). Note: h4 is connected to s3.
      - Uses only chain links.
      - Stores iperf logs and TCP info for each host.
    """
    info("\n***** Running Experiment (b) *****\n")
    result_dir = f"results/experiment_b/{cc}/"
    create_dir(result_dir)
    
    h1 = net.get('h1')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h7 = net.get('h7')

    server_log = os.path.join(result_dir, "h7_server.log")
    h1_client_log = os.path.join(result_dir, "h1_client.log")
    h3_client_log = os.path.join(result_dir, "h3_client.log")
    h4_client_log = os.path.join(result_dir, "h4_client.log")
    
    info("Starting iperf server on h7...\n")
    # 'while true; do iperf3 -s -p 5201 --one-off; done'
    h7.cmd(f"while true; do iperf3 -s -p 5201 --one-off; done > {server_log} 2>&1 &")
    info("Server started... \n")
    time.sleep(2)
    
    info("Starting iperf client on h1 (duration 150s)...\n")
    h1.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h1_client_log))

    info("Waiting 15 seconds before starting h3...\n")
    time.sleep(15)

    info("\nStarting iperf client on h3 (duration 120s)...\n")
    h3.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 120 -C %s > %s 2>&1 &" % (h7.IP(), cc, h3_client_log))

    info("Waiting 15 seconds before starting h4...\n")
    time.sleep(15)
    
    info("\nStarting iperf client on h4 (duration 90s)...\n")
    h4.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 90 -C %s > %s 2>&1 &" % (h7.IP(), cc, h4_client_log))
    time.sleep(120+5)
    
    # Terminate iperf server and remaining processes
    h7.cmd("pkill -f iperf3")
    info("Experiment (b) completed. Results stored in %s\n" % result_dir)

def experiment_c(net, cc, loss_rate):
    """
    Experiment (c): Bandwidth-limited and lossy links with extra links.
      The experiment is divided into four sub-experiments:
        c1. Only link s2-s4 active (client: h3).
        c2a. Only link s1-s4 active with clients h1 and h2.
        c2b. Only link s1-s4 active with clients h1 and h3.
        c2c. Only link s1-s4 active with clients h1, h3, and h4.
      For each sub-experiment, logs and TCP info are stored in dedicated subdirectories.
    """
    info("\n***** Running Experiment (c) *****\n")
    base_dir = "results/experiment_c"
    create_dir(base_dir)
    
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h7 = net.get('h7')
    for host in [h1, h2, h3, h4, h7]:
        set_tcp_cc(host, cc)
    
    # Sub-experiment c1: Only link s2-s4 active (client: h3)
    c1_dir = os.path.join(base_dir, "c1")
    create_dir(c1_dir)
    server_log = os.path.join(c1_dir, "h7_server.log")
    client_log = os.path.join(c1_dir, "h3_client.log")
    tcpinfo_h3_log = os.path.join(c1_dir, "h3_tcp_info.log")
    tcpinfo_h7_log = os.path.join(c1_dir, "h7_tcp_info.log")
    info("\n--- Experiment (c1): Only link s2-s4 active (h3 -> h7) ---\n")
    net.configLinkStatus('s1', 's2', 'down')
    net.configLinkStatus('s2', 's3', 'down')
    net.configLinkStatus('s3', 's4', 'down')
    net.configLinkStatus('s1', 's4', 'down')
    time.sleep(2)
    run_iperf_server(h7, logfile=server_log)
    time.sleep(2)
    run_iperf_client(h3, h7.IP(), duration=150, cc=cc, logfile=client_log)
    time.sleep(5)
    h7.cmd("pkill -f iperf3")
    store_tcp_info(h3, tcpinfo_h3_log)
    store_tcp_info(h7, tcpinfo_h7_log)
    # Restore links
    net.configLinkStatus('s1', 's2', 'up')
    net.configLinkStatus('s2', 's3', 'up')
    net.configLinkStatus('s3', 's4', 'up')
    net.configLinkStatus('s1', 's4', 'up')
    time.sleep(5)
    
    # Sub-experiment c2a: Only link s1-s4 active with clients h1 and h2
    c2a_dir = os.path.join(base_dir, "c2a")
    create_dir(c2a_dir)
    server_log = os.path.join(c2a_dir, "h7_server.log")
    h1_client_log = os.path.join(c2a_dir, "h1_client.log")
    h2_client_log = os.path.join(c2a_dir, "h2_client.log")
    tcpinfo_h1_log = os.path.join(c2a_dir, "h1_tcp_info.log")
    tcpinfo_h2_log = os.path.join(c2a_dir, "h2_tcp_info.log")
    tcpinfo_h7_log = os.path.join(c2a_dir, "h7_tcp_info.log")
    info("\n--- Experiment (c2a): Only link s1-s4 active (h1, h2 -> h7) ---\n")
    net.configLinkStatus('s1', 's2', 'down')
    net.configLinkStatus('s2', 's3', 'down')
    net.configLinkStatus('s3', 's4', 'down')
    net.configLinkStatus('s2', 's4', 'down')
    time.sleep(2)
    run_iperf_server(h7, logfile=server_log)
    time.sleep(2)
    h1.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h1_client_log))
    h2.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h2_client_log))
    time.sleep(150)
    h7.cmd("pkill -f iperf3")
    store_tcp_info(h1, tcpinfo_h1_log)
    store_tcp_info(h2, tcpinfo_h2_log)
    store_tcp_info(h7, tcpinfo_h7_log)
    # Restore links
    net.configLinkStatus('s1', 's2', 'up')
    net.configLinkStatus('s2', 's3', 'up')
    net.configLinkStatus('s3', 's4', 'up')
    net.configLinkStatus('s2', 's4', 'up')
    time.sleep(5)
    
    # Sub-experiment c2b: Only link s1-s4 active with clients h1 and h3
    c2b_dir = os.path.join(base_dir, "c2b")
    create_dir(c2b_dir)
    server_log = os.path.join(c2b_dir, "h7_server.log")
    h1_client_log = os.path.join(c2b_dir, "h1_client.log")
    h3_client_log = os.path.join(c2b_dir, "h3_client.log")
    tcpinfo_h1_log = os.path.join(c2b_dir, "h1_tcp_info.log")
    tcpinfo_h3_log = os.path.join(c2b_dir, "h3_tcp_info.log")
    tcpinfo_h7_log = os.path.join(c2b_dir, "h7_tcp_info.log")
    info("\n--- Experiment (c2b): Only link s1-s4 active (h1, h3 -> h7) ---\n")
    net.configLinkStatus('s1', 's2', 'down')
    net.configLinkStatus('s2', 's3', 'down')
    net.configLinkStatus('s3', 's4', 'down')
    net.configLinkStatus('s2', 's4', 'down')
    time.sleep(2)
    run_iperf_server(h7, logfile=server_log)
    time.sleep(2)
    h1.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h1_client_log))
    h3.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h3_client_log))
    time.sleep(150)
    h7.cmd("pkill -f iperf3")
    store_tcp_info(h1, tcpinfo_h1_log)
    store_tcp_info(h3, tcpinfo_h3_log)
    store_tcp_info(h7, tcpinfo_h7_log)
    # Restore links
    net.configLinkStatus('s1', 's2', 'up')
    net.configLinkStatus('s2', 's3', 'up')
    net.configLinkStatus('s3', 's4', 'up')
    net.configLinkStatus('s2', 's4', 'up')
    time.sleep(5)
    
    # Sub-experiment c2c: Only link s1-s4 active with clients h1, h3, and h4
    c2c_dir = os.path.join(base_dir, "c2c")
    create_dir(c2c_dir)
    server_log = os.path.join(c2c_dir, "h7_server.log")
    h1_client_log = os.path.join(c2c_dir, "h1_client.log")
    h3_client_log = os.path.join(c2c_dir, "h3_client.log")
    h4_client_log = os.path.join(c2c_dir, "h4_client.log")
    tcpinfo_h1_log = os.path.join(c2c_dir, "h1_tcp_info.log")
    tcpinfo_h3_log = os.path.join(c2c_dir, "h3_tcp_info.log")
    tcpinfo_h4_log = os.path.join(c2c_dir, "h4_tcp_info.log")
    tcpinfo_h7_log = os.path.join(c2c_dir, "h7_tcp_info.log")
    info("\n--- Experiment (c2c): Only link s1-s4 active (h1, h3, h4 -> h7) ---\n")
    net.configLinkStatus('s1', 's2', 'down')
    net.configLinkStatus('s2', 's3', 'down')
    net.configLinkStatus('s3', 's4', 'down')
    net.configLinkStatus('s2', 's4', 'down')
    time.sleep(2)
    run_iperf_server(h7, logfile=server_log)
    time.sleep(2)
    h1.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h1_client_log))
    h3.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h3_client_log))
    h4.cmd("iperf3 -c %s -p 5201 -b 10M -P 10 -t 150 -C %s > %s 2>&1 &" % (h7.IP(), cc, h4_client_log))
    time.sleep(150)
    h7.cmd("pkill -f iperf3")
    store_tcp_info(h1, tcpinfo_h1_log)
    store_tcp_info(h3, tcpinfo_h3_log)
    store_tcp_info(h4, tcpinfo_h4_log)
    store_tcp_info(h7, tcpinfo_h7_log)
    # Restore all links (ensure extra links are up)
    net.configLinkStatus('s1', 's2', 'up')
    net.configLinkStatus('s2', 's3', 'up')
    net.configLinkStatus('s3', 's4', 'up')
    net.configLinkStatus('s2', 's4', 'up')
    net.configLinkStatus('s1', 's4', 'up')
    time.sleep(5)
    
    info("\nExperiment (c) completed. Results stored in %s\n" % base_dir)



###########################
# Main Function
###########################

def main():
    setLogLevel('info')
    parser = argparse.ArgumentParser(description="Mininet Topology for TCP Congestion Control Experiments")
    parser.add_argument('--option', type=str, default='a', help="Experiment option: a, b, or c")
    parser.add_argument('--cc', type=str, default='reno', help="TCP congestion control scheme: reno, vegas, or htcp")
    parser.add_argument('--loss', type=float, default=0, help="Link loss rate (in percent) for s2-s3 link (only for experiment c)")
    args = parser.parse_args()

    allowed_cc = ['reno', 'vegas', 'htcp']
    if args.cc.lower() not in allowed_cc:
        info("Invalid TCP congestion control scheme. Allowed: reno, vegas, htcp\n")
        sys.exit(1)
    cc_scheme = args.cc.lower()

    # For experiment (c) enable bandwidth configuration and extra links.
    bw_config = True if args.option == 'c' else False
    topo = CongestionTopo(bw_config=bw_config, loss_rate=args.loss)
    net = Mininet(topo=topo, link=TCLink, switch=OVSSwitch, controller=Controller('c0'),autoStaticArp=True)

    net.start()
    
    info("Mininet is up.\n")

    if args.option == 'a':
        experiment_a(net, cc_scheme)
    elif args.option == 'b':
        experiment_b(net, cc_scheme)
    elif args.option == 'c':
        experiment_c(net, cc_scheme, args.loss)
    else:
        info("Invalid option. Use --option=a, b, or c.\n")
        net.stop()
        sys.exit(1)

    info("\n*** You now have a Mininet CLI for further debugging or capturing. ***\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
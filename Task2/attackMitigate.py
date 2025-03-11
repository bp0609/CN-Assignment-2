import subprocess
import time
import threading
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info

class CustomNetwork(Topo):
    def build(self):
        client = self.addHost('hostA')
        server = self.addHost('hostB')
        switch = self.addSwitch('sw1')

        self.addLink(client, switch, bw=10)
        self.addLink(switch, server, bw=10)


def initiate_legit_traffic(source, destination_ip, port):
    source.cmd(f'''
                while true; 
                do nc {destination_ip} {port} <<< "Hello, Server";
                sleep 2;
                done &
            ''')


def trigger_syn_flood(source, destination_ip, port):
    source.cmd(f'hping3 -S -p {port} --flood --rand-source {destination_ip} &')

setLogLevel('info')
topology = CustomNetwork()
network = Mininet(topology)
network.start()

info("Checking connectivity in the network\n")
network.pingAll()

client, server = network.get('hostA', 'hostB')
destination_ip = server.IP()
destination_port = 9090

# Updating network settings to mitigate SYN flood attack
server.cmd('sysctl -w net.ipv4.tcp_max_syn_backlog=150')
server.cmd('sysctl -w net.ipv4.tcp_syncookies=1')
server.cmd('sysctl -w net.ipv4.tcp_synack_retries=4')

client.cmd(f'tcpdump -w syn_mitigation.pcap -i {client.defaultIntf()} tcp &')
time.sleep(1)

legit_traffic_thread = threading.Thread(target=initiate_legit_traffic, args=(client, destination_ip, destination_port))
legit_traffic_thread.start()

time.sleep(20)
syn_attack_start = time.time()

syn_flood_thread = threading.Thread(target=trigger_syn_flood, args=(client, destination_ip, destination_port))
syn_flood_thread.start()

time.sleep(100)
syn_attack_end = time.time()

client.cmd('pkill hping3')
syn_flood_thread.join()

time.sleep(20)

client.cmd('pkill nc')
legit_traffic_thread.join()

client.cmd('pkill tcpdump')
network.stop()

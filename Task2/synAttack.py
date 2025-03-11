import subprocess
import time
import threading
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info

class NetworkTopology(Topo):
    def build(self):
        client_node = self.addHost('h1')
        server_node = self.addHost('h2')
        network_switch = self.addSwitch('s1')

        self.addLink(client_node, network_switch, bw=10)
        self.addLink(network_switch, server_node, bw=10)

def begin_benign_connection(node, target_ip, port):
    node.cmd(f'''while true; do nc {target_ip} {port} <<< "Hello";
                sleep 1; done &''')

def initiate_syn_attack(node, target_ip, port):
    node.cmd(f'hping3 -S -p {port} --flood --rand-source {target_ip} &')

setLogLevel('info')
custom_topo = NetworkTopology()
network = Mininet(custom_topo)
network.start()

info("Verifying network connections\n")
network.pingAll()

client, server = network.get('h1', 'h2')
target_ip = server.IP()
port = 8080

server.cmd('sysctl -w net.ipv4.tcp_max_syn_backlog=10000')
server.cmd('sysctl -w net.ipv4.tcp_syncookies=0')
server.cmd('sysctl -w net.ipv4.tcp_synack_retries=1')

client.cmd(f'tcpdump -w SYN_attack.pcap -i {client.defaultIntf()} tcp &')
time.sleep(1)

benign_thread = threading.Thread(target=begin_benign_connection, 
                                args=(client, target_ip, port))
benign_thread.start()

time.sleep(20)
attack_begin = time.time()

attack_thread = threading.Thread(target=initiate_syn_attack,
                               args=(client, target_ip, port))
attack_thread.start()

time.sleep(100)
attack_conclusion = time.time()

client.cmd('pkill hping3')
attack_thread.join()

time.sleep(20)

client.cmd('pkill nc')
benign_thread.join()

client.cmd('pkill tcpdump')
network.stop()
from mininet.net import Mininet
from mininet.node import Controller
import time
from mininet.topo import Topo

class customTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1')
        h7 = self.addHost('h7', ip='10.0.0.7')
        self.addLink(h1, h7, bw=100)  

topos = {'task3_topo': (lambda: customTopo())}

def run_experiment():
    net = Mininet(topo=customTopo(), controller=Controller)
    net.start()

    h1 = net.get('h1')
    h7 = net.get('h7')

    configs = [
        (1, 1),  # Nagle ON, Delayed-ACK ON
        (1, 0),  # Nagle ON, Delayed-ACK OFF
        (0, 1),  # Nagle OFF, Delayed-ACK ON
        (0, 0)   # Nagle OFF, Delayed-ACK OFF
    ]

    for idx, (nagle, delay_ack) in enumerate(configs, 1):
        print(f"\nTEST {idx}: Nagle={'ON' if nagle else 'OFF'}, Delayed-ACK={'ON' if delay_ack else 'OFF'}\n")

        h7.cmd(f'python3 server.py --nagle={nagle} --delay_ack={delay_ack} > server_{idx}.log 2>&1 &')
        time.sleep(5)

        # Start packet capture
        pcap = f"task3_{idx}.pcap"
        h7.cmd(f'tcpdump -i h7-eth0 -w {pcap} &')
        time.sleep(2)

        # Run client
        h1.cmd(f'python3 client.py --nagle={nagle} --delay_ack={delay_ack} > client_{idx}.log 2>&1')

        # Cleanup
        time.sleep(5) 
        h7.cmd('killall tcpdump; pkill -f server.py')
        time.sleep(2) 

    net.stop()

if __name__ == '__main__':
    run_experiment()
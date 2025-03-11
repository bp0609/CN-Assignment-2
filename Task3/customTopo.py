from mininet.topo import Topo

class Task3Topo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1')
        h7 = self.addHost('h7', ip='10.0.0.7')
        self.addLink(h1, h7, bw=100)  

topos = {'task3_topo': (lambda: Task3Topo())}
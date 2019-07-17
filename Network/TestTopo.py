#!/usr/bin/python
# Luke Hall B425724 - MSc Dissertation Project
# TestTop - Testing custom network topology configuration

# $ sudo Network/TestTopo.py

# Mininet imports
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.topo import SingleSwitchTopo
from mininet.topolib import TreeNet
from mininet.net import Mininet
from mininet.node import RemoteController, Ryu

class TestTopo(SingleSwitchTopo):
    """ Testing custom topology of N hosts"""
    
    def build(self, N, **kwargs):
        """
        Override topology build method
        param N: Number of hosts to put in network
        """
        # Create N hosts
        hosts = [self.addHost('h%s' % h) 
                    for h in range(1, N+1)]
        # Create switch
        switch = self.addSwitch('s1')
        
        # Create links between switch & hosts
        for host in hosts:
            self.addLink(host, switch)

# Add topology to topology dictionary
topos = { 'TestTopo': TestTopo }

if __name__ == "__main__":
    lg.setLogLevel('info')
    
    # Define number of hosts
    hostCount = 5
    
    # Add network (by creating a Mininet object of the network)
    net = Mininet(topo=TestTopo(hostCount))
    
    # Add Remote Controller
    info("*** Adding remote controller\n")
    net.addController(name='Remote_c0',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        port=7777)
    
    # Add NAT
    info("*** Adding NAT\n")
    net.addNAT().configDefault()
    net.start()
    
    # Enable ssh on hosts
    
    # Start network & startup info messages
    info("*** %s hosts are running and should be connected to internet\n" % hostCount)
    info("*** Type 'exit' or control-D to shut down network\n")
    
    CLI(net)
    
    # Shut down NAT
    net.stop()

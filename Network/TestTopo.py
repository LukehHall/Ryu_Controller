#!/usr/bin/python
# Luke Hall B425724 - MSc Dissertation Project
# TestTop - Testing custom network topology configuration

# $ sudo Network/TestTopo.py

# Mininet imports
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.topo import SingleSwitchTopo
from mininet.net import Mininet
from mininet.node import RemoteController, Node
from mininet.util import waitListening

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

def connectToRootNS(network, switch, ip, routes):
    """
    Connect hosts to root namespace via switch, starts network
    param network: Mininet() network object
    param switch: switch to connect to root namespace
    param ip: IP address for root node
    param routes: host networks to route to
    """
    # Create a node in root namespace and link to switch 0
    root = Node( 'root', inNamespace=False )
    intf = network.addLink( root, switch ).intf1
    root.setIP( ip, intf=intf )
    # Start network that now includes link to root namespace
    # network.start()
    # Add routes from root ns to hosts
    for route in routes:
        root.cmd( 'route add -net ' + route + ' dev ' + str( intf ) )

def sshd(network, cmd='/usr/sbin/sshd', opts='-D -o UseDNS=no -u0',
            ip='10.123.123.1/32', routes=None, switch=None):
    """
    Start up ssh daemons on all hosts.
    param ip: root-eth0 IP address in root namespace (10.123.123.1/32)
    param routes: Mininet host networks to route to (10.0/24)
    param switch: Mininet switch to connect to root namespace (s1) 
    """
    if not switch:
        switch = network['s1']
    if not routes:
        routes = ['10.0.0.0/24']
    connectToRootNS(network, switch, ip, routes)
    for host in network.hosts:
        host.cmd(cmd + ' ' + opts + '&')
    info("*** Waiting for ssh daemons to start\n")
    for server in network.hosts:
        waitListening(server=server, port=22, timeout=5)
        
    info( "\n*** Hosts are running sshd at the following addresses:\n" )
    for host in network.hosts:
        info( host.name, host.IP(), '\n' )

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
    
    # Enable ssh on hosts
    sshd(net)
    
    # Add NAT
    info("*** Adding NAT\n")
    net.addNAT().configDefault()
    net.start()
    
    # Start network & startup info messages
    info("*** %s hosts are running and should be connected to internet\n" % hostCount)
    info("*** Type 'exit' or control-D to shut down network\n")
    
    CLI(net)
    
    # Shut down NAT
    net.stop()

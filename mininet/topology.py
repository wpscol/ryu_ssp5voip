#!/usr/bin/env python3

from logging import getLogger
from time import sleep

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI

log = getLogger("py3mininet")


class SSP5VoipTopology(Topo):
    def build(self):
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")

        # Switches
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")
        s6 = self.addSwitch("s6")

        # Links
        self.addLink(h1, s1)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s1, s5)
        self.addLink(s5, s6)
        self.addLink(s3, s2)
        self.addLink(s4, s2)
        self.addLink(s6, s2)
        self.addLink(s2, h2)


def configure_tc(net):
    for link in net.links:
        for intf in (link.intf1, link.intf2):
            intf.config(bw=10.0, delay="2ms")


def start_traffic(net):
    """Starts permanent traffic generation between hosts."""
    h1 = net.get("h1")
    h2 = net.get("h2")

    srv_ip = h2.IP()

    info(f"*** Starting iperf SERVERS on {h2.name} ({srv_ip})...\n")
    h2.cmd("iperf -s -p 4001 &")
    h2.cmd("iperf -s -p 4002 &")
    # h2.cmd("iperf -s -u -p 5003 &")

    info(f"*** Starting iperf CLIENTS on {h1.name} connecting to {h2.name}...\n")
    h1.cmd(f"iperf -c {srv_ip} -p 4001 -t 99999 &")
    h1.cmd(f"iperf -c {srv_ip} -p 4002 -t 99999 &")
    # h1.cmd(f"iperf -c {srv_ip} -p 5003 -u -t 99999 &")


def main():
    topo = SSP5VoipTopology()
    net = Mininet(
        topo=topo, controller=None, autoSetMacs=True, autoStaticArp=True, link=TCLink
    )

    # Note: Ensure a controller (like Ryu) is running on port 6633 locally
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)

    net.start()
    configure_tc(net)

    info("\n*** Waiting 45 seconds for STP to converge...\n")
    sleep(45)

    # start_traffic(net)

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()

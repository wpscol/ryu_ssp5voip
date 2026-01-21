#!/usr/bin/env python3

from logging import getLogger
from time import sleep
import random

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
    """Starts realistic bursty traffic generation between hosts with random patterns."""
    h1 = net.get("h1")
    h2 = net.get("h2")

    srv_ip = h2.IP()

    info(f"*** Starting iperf SERVERS on {h2.name} ({srv_ip})...\n")
    h2.cmd("iperf -s -p 4001 &")
    h2.cmd("iperf -s -p 4002 &")
    h2.cmd("iperf -s -p 4003 &")
    h2.cmd("iperf -s -p 4004 &")

    info(f"*** Starting realistic bursty iperf CLIENTS on {h1.name}...\n")

    # Generator 1: Frequent small bursts simulating API calls (50-200 KB every 0.5-2 seconds)
    h1.cmd(f"""bash -c 'while true; do
        sleep $(awk "BEGIN {{print (RANDOM % 15 + 5) / 10}}");
        size=$((50 + RANDOM % 151))K;
        iperf -c {srv_ip} -p 4001 -n $size;
    done' &""")

    # Generator 2: Very frequent tiny bursts simulating messaging (10-50 KB every 0.3-1 second)
    h1.cmd(f"""bash -c 'while true; do
        sleep $(awk "BEGIN {{print (RANDOM % 7 + 3) / 10}}");
        size=$((10 + RANDOM % 41))K;
        iperf -c {srv_ip} -p 4002 -n $size;
    done' &""")

    # Generator 3: Frequent medium bursts simulating web pages (100-400 KB every 1-3 seconds)
    h1.cmd(f"""bash -c 'while true; do
        sleep $((1 + RANDOM % 3));
        size=$((100 + RANDOM % 301))K;
        iperf -c {srv_ip} -p 4003 -n $size;
    done' &""")

    # Generator 4: Medium-frequent bursts simulating streaming chunks (200-800 KB every 1-4 seconds)
    h1.cmd(f"""bash -c 'while true; do
        sleep $((1 + RANDOM % 4));
        size=$((200 + RANDOM % 601))K;
        iperf -c {srv_ip} -p 4004 -n $size;
    done' &""")

    info("*** Traffic generators started with random burst patterns\n")


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

    start_traffic(net)

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()

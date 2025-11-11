#!/usr/bin/env python3

from logging import getLogger
from time import sleep

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.log import setLogLevel
from mininet.cli import CLI

log = getLogger("py3mininet")


class SSP5VoipTopology(Topo):
  def build(self):
    h1 = self.addHost("h1")
    h2 = self.addHost("h2")

    # Switches
    s1 = self.addSwitch('s1')
    s2 = self.addSwitch('s2')
    s3 = self.addSwitch('s3')
    s4 = self.addSwitch('s4')
    s5 = self.addSwitch('s5')
    s6 = self.addSwitch('s6')

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


def main():
  topo = SSP5VoipTopology()

  net = Mininet(topo=topo, controller=None, autoSetMacs=True, autoStaticArp=True, link=TCLink)
  net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
  net.start()

  # remove loops (STP)
  for sw in net.switches:
    sw.cmd('ovs-vsctl set-fail-mode', sw, 'standalone')
    sw.cmd('ovs-vsctl set Bridge', sw, 'stp_enable=true')

  # Configure TC
  for link in net.links:
    for intf in (link.intf1, link.intf2):
      intf.config(bw=5, delay='15ms')

  CLI(net)
  net.stop()


if __name__ == "__main__":
  setLogLevel("info")
  main()
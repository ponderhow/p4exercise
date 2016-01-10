#!/usr/bin/python

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep
import os
import subprocess

_THIS_DIR = os.path.dirname(os.path.realpath(__file__))
_THRIFT_BASE_PORT = 22222

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--cli', help='Path to BM CLI',
                    type=str, action="store", required=True)

args = parser.parse_args()


def build_topo(net, topo_conf):
    hosts = {}
    switches = {}
    cpu_r = 1. / len(topo_conf)
    for i, u in enumerate(topo_conf):
        h = net.addHost('h{0}'.format(i+1), cpu=cpu_r)
        s = net.addSwitch('s{0}'.format(i+1))
        net.addLink(h, s)  # xxx
        hosts[u] = h
        switches[u] = s

    output_ports = {}
    for u in topo_conf:
        for v in topo_conf[u]:
            if (u, v) in output_ports:
                continue
            s_u = switches[u]
            s_v = switches[v]
            port_u = s_u.newPort()
            port_v = s_v.newPort()

            net.addLink(s_u, s_v, port1=port_u, port2=port_v, cls=TCLink, **topo_conf[u][v])
            output_ports[(u, v)] = port_u
            output_ports[(v, u)] = port_v

    return hosts, switches, output_ports

def run(topo_conf, tunnels, old_trf, new_trf, default_route={}, ryu_controller='./cuphook.py'):
    setLogLevel('info')
    net = Mininet(autoSetMacs=True, autoStaticArp=True, controller=RemoteController)
    hosts, switches, output_ports = build_topo(net, topo_conf)

    with open('outports.txt', 'w') as f:
        for k in sorted(output_ports):
            print(k, output_ports[k], file=f)

    c0 = net.addController('c0')

    net.start()
    set_of_version(switches.values())
    gen_default_rules(hosts, switches, output_ports, default_route)
    gen_tunnel_rules(hosts, switches, output_ports, old_trf, new_trf, tunnels)

    # start controller
    c0.cmdPrint('ryu-manager --verbose {0} &'.format(ryu_controller))
    #time.sleep(10)
    net.iperf()
    CLI(net)
    net.stop()


class MyTopo(Topo):
    def __init__(self, sw_path, json_path, nb_hosts, nb_switches, links, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        for i in xrange(nb_switches):
            switch = self.addSwitch('s%d' % (i + 1),
                                    sw_path = sw_path,
                                    json_path = json_path,
                                    thrift_port = _THRIFT_BASE_PORT + i,
                                    pcap_dump = False, #True,
                                    device_id = i)

        for h in xrange(nb_hosts):
            host = self.addHost('h%d' % (h + 1))

        for a, b in links:
            self.addLink(a, b)

def read_topo():
    nb_hosts = 0
    nb_switches = 0
    links = []
    with open("topo.txt", "r") as f:
        line = f.readline().strip()
        w, nb_switches = line.split()
        assert(w == "switches")
        line = f.readline().strip()
        w, nb_hosts = line.split()
        assert(w == "hosts")
        for line in f:
            if not f: break
            line = line.strip()
            a, b = line.split()
            links.append( (a, b) )
    return int(nb_hosts), int(nb_switches), links


def main():
    nb_hosts, nb_switches, links = read_topo()

    topo = MyTopo(args.behavioral_exe,
                  args.json,
                  nb_hosts, nb_switches, links)

    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None,
                  autoStaticArp = True)
    net.start()

    for n in xrange(nb_hosts):
        h = net.get('h%d' % (n + 1))
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            print cmd
            h.cmd(cmd)
        print "disable ipv6"
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv4.tcp_congestion_control=reno")
        h.cmd("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")

    sleep(1)

    for i in xrange(nb_switches):
        cmd = [args.cli, "--json", args.json,
               "--thrift-port", str(_THRIFT_BASE_PORT + i)]
        with open("commands.txt", "r") as f:
            print " ".join(cmd)
            try:
                output = subprocess.check_output(cmd, stdin = f)
                print output
            except subprocess.CalledProcessError as e:
                print e
                print e.output

    sleep(1)

    print "Ready !"

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()

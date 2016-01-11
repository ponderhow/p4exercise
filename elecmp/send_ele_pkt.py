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

from scapy.all import sniff, sendp, hexdump
from scapy.all import Packet, Ether, IP, TCP
from scapy.all import ShortField, IntField, LongField, BitField, ByteField

import sys


class BytePkt(Packet):
    name = "BytePkt"
    fields_desc = [
        ByteField("val", 0)
    ]


def main():
    if len(sys.argv) < 3:
        print "Usage: send_ele_pkt.py [pkt_num] [tcp_sport] [tcp_dport] [nhop_1, nhop_2, ...]"
        #print "For example: send_ele_pkt.py  1 2"
        sys.exit(1)

    pkt_num   = int(sys.argv[1])
    tcp_sport = int(sys.argv[2])
    tcp_dport = int(sys.argv[3])
    if len(sys.argv) is 4:
        tcp_res = 0
    else:
        tcp_res = 4

    p = Ether(dst="00:00:00:00:00:02")/IP(dst="10.0.0.2")/TCP(reserved=tcp_res, sport=tcp_sport, dport=tcp_dport)

    if tcp_res == 4:
        p = p / BytePkt(val=len(sys.argv[4:]))
        for s in sys.argv[4:]:
            p = p / BytePkt(val=int(s))
            
    for i in range(pkt_num):
        pp = p #/ 'hello-{0}'.format(i)
        print pp.show()
        hexdump(pp)
        sendp(pp, iface = "eth0")


if __name__ == '__main__':
    main()

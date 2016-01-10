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

from scapy.all import sniff, sendp
from scapy.all import Packet, Ether
from scapy.all import ShortField, IntField, LongField, BitField

import sys

class MagicPkt(Packet):
    name = "magicpkt"
    fields_desc = [
        IntField("flowID", 0),
        IntField("pathID", 0)
    ]

def main():
    if len(sys.argv) != 3:
        print "Usage: send_magic_pkt.py [flowID] [target_pathID]"
        print "For example: send_magic_pkt.py  1 2"
        sys.exit(1)

    flowID, pathID = sys.argv[1:]

    p = Ether(type=0x101, dst="ff:ff:ff:ff:ff:ff") / MagicPkt(flowID=int(flowID), pathID=int(pathID))
    print p.show()
    sendp(p, iface = "eth0")
    # print msg

if __name__ == '__main__':
    main()

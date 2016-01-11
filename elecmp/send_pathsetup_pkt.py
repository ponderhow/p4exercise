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

from scapy.all import sniff, sendp, send
from scapy.all import Packet, Ether, IP, TCP
from scapy.all import ShortField, IntField, LongField, BitField, ByteField

from time import sleep

import sys
import random

class BytePkt(Packet):
    name = "BytePkt"
    fields_desc = [
        ByteField("val", 0)
    ]

def main():
    n = 4
    for i in range(n):
        p = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="10.0.0.2")/TCP(reserved=2, dport=49152+i) / BytePkt(val=0)
        # !!!! there is an error in scapy. The TCP stack still use 4 bit for the reserved key.
        print p.show()
        sendp(p, iface = "eth0")
        #p = IP(dst="10.0.0.2")/TCP(reserved=2, dport=10000+i)
        # !!!! there is an error in scapy. The TCP stack still use 4 bit for the reserved key.
        #print p.show()
        #send(p)

        sleep(1)
    # print msg

if __name__ == '__main__':
    main()

/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list; // ipv4 only calc the header parts
    }
    algorithm : csum16;
    output_width : 16;
}


calculated_field ipv4.hdrChecksum  {
    //verify ipv4_
    //update ipv4_checksum;
    update ipv4_checksum if(valid(ipv4));
}


#define IP_PROTOCOLS_TCP    0x06
#define IP_PROTOCOLS_UDP    0x11

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

header tcp_t tcp;

#define NORMAL_TCP 0
//
#define ELEPATH_SETUP 1
#define EXPLICIT_ELENHOP 2
#define TCP_RES_NONE 7
#define FEEDBACK_PORT_NUM 4
#define UNUSED_PORT_NUM 1

parser parse_tcp {
    extract(tcp);
    //set_metadata(ingress_metadata.ecmp_flag, 1);
    return select(latest.res) {
        EXPLICIT_ELENHOP : parse_ele_nhop_num;
        ELEPATH_SETUP : parse_ele_nhop_num;
        default: ingress;
    }
}

header elenhop_counter_t elenhop_counter;

parser parse_ele_nhop_num {
    extract(elenhop_counter);
    return select(tcp.res) {
        EXPLICIT_ELENHOP : parse_ele_nhop;
        default: ingress;
    }
}

header elenhop_header_t elenhop_header;

parser parse_ele_nhop {
    extract(elenhop_header);
    return ingress;
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    return select(latest.dstPort) {
        UNUSED_PORT_NUM : parse_flow_fingerprint; // trick desgin
        // The P4 program should/MUST be capable of parsing every packet it can produce
        // http://mail.p4.org/pipermail/p4-dev_p4.org/2015-December/000385.html
        default: ingress;
    }
}

header flow_fingerprint_t flow_fingerprint;

parser parse_flow_fingerprint {
    extract(flow_fingerprint);
    return ingress;
}

//@pragma header_ordering ethernet ipv4 udp flow_fingerprint tcp elenhop_counter elenhop_header

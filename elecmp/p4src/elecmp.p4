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

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/intrinsic.p4"

#define ECMP_BIT_WIDTH 10
#define ECMP_GROUP_TABLE_SIZE 1024
#define ECMP_NHOP_TABLE_SIZE 16384
#define NHOP_BIT_WIDTH 8
#define EDGE_TABLE_SIZE 1024
#define DEFAULT_ROUTE_TABLE_SIZE 1024

header_type ingress_metadata_t {
    fields {
        ecmp_grp_id : ECMP_NHOP_ID_BIT_WIDTH;
        ecmp_grp_size : ECMP_NHOP_ID_BIT_WIDTH;
        ecmp_nhop_id : 14; // offset in the ecmp group

        elenhop : NHOP_BIT_WIDTH;

        elecounter : 32;

        is_edge_node : 1;
        is_routed : 1;
        ecmp_flag : 1;

        ether_srcAddr: 48;
        ether_dstAddr: 48;
    }
}

metadata ingress_metadata_t ingress_metadata;

action set_edge_flag() {
    modify_field(ingress_metadata.is_edge_node, 1);
}

action _nop() {
}

action _drop() {
    drop();
}

action set_nhop(port) {
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ingress_metadata.is_routed, 1);
    add_to_field(ipv4.ttl, -1);
}

table edge_check {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        _nop;
        set_edge_flag;
    }
    size : EDGE_TABLE_SIZE;
}

table default_route {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        _drop;
        set_nhop;
    }
    size : DEFAULT_ROUTE_TABLE_SIZE;
}


field_list l3_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

action set_ecmp_grp_id(ecmp_grp_id) {
    modify_field(ingress_metadata.ecmp_grp_id, ecmp_grp_id);
}

/*
action no_ecmp() {
    modify_field(ingress_metadata.ecmp_grp_id, 0);
}
*/

table default_ecmp_group {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        _nop;
        set_ecmp_grp_id;
    }
    size : ECMP_GROUP_TABLE_SIZE;
}

field_list_calculation ecmp_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : ECMP_BIT_WIDTH;
}

action fix_ecmp_elenhop_id() {
    modify_field(ingress_metadata.ecmp_nhop_id, elenhop_header.ecmp_nhop_id);
    remove_header(elenhop_header);
    subtract_from_field(elenhop_counter.val, 1);
    subtract_from_field(ipv4.totalLen, ECMP_NHOP_ID_BIT_WIDTH >> 3);
}

table fix_elenhop {
    actions { fix_ecmp_elenhop_id; }
}

action remove_explicit_flag() {
    modify_field(tcp.res, 4);
    // ########################################################################
    // P4 switch has BUG!!!
    // why 0 does not work?
    // I write the field as 4, but it's shown as 6 (i.e., 4 + 2) in runtime.
    // #######################################################################
    remove_header(elenhop_counter);
    subtract_from_field(ipv4.totalLen, ECMP_NHOP_COUNT_BIT_WIDTH >> 3);
}

table clean_res_flag {
    actions { remove_explicit_flag; }
}

action set_ecmp_nhop_select(ecmp_grp_size) {
    modify_field(ingress_metadata.ecmp_grp_size, ecmp_grp_size);
    modify_field_with_hash_based_offset(ingress_metadata.ecmp_nhop_id, 0,
                                        ecmp_hash, ecmp_grp_size);
    // why the 2nd and 4th parameter of modify_field_with_hash_based_offset
    // must be VAL ?
}

table normal_ecmp_hash {
    reads {
        ingress_metadata.ecmp_grp_id : exact;
    }
    actions {
        _nop;
        set_ecmp_nhop_select;
    }
    size : ECMP_GROUP_TABLE_SIZE;
}

register elecounter_in_ecmp_grp {
    width : 32;
    instance_count : ECMP_GROUP_TABLE_SIZE;
}

field_list elecounter_hash_fields {
    ingress_metadata.elecounter;
}

field_list_calculation elecounter_hash {
    input {
        elecounter_hash_fields;
    }
    algorithm : identity;
    output_width : ECMP_NHOP_ID_BIT_WIDTH;
}

action push_elenhop_id(ecmp_grp_size) {
    // step-1: calc ecmp_nhop_id for elephant flow and set it
    register_read(ingress_metadata.elecounter,
                  elecounter_in_ecmp_grp, ingress_metadata.ecmp_grp_id);

    modify_field_with_hash_based_offset(ingress_metadata.ecmp_nhop_id, 0,
                            elecounter_hash, ecmp_grp_size);

    add_to_field(ingress_metadata.elecounter, 1);
    register_write(elecounter_in_ecmp_grp, ingress_metadata.ecmp_grp_id,
                 ingress_metadata.elecounter);

    // push this info into the payload
    add_header(elenhop_header);
    modify_field(elenhop_header.ecmp_nhop_id, ingress_metadata.ecmp_nhop_id);
    add_to_field(elenhop_counter.val, 1);
    add_to_field(ipv4.totalLen, ECMP_NHOP_ID_BIT_WIDTH >> 3);
}

table robin_ele_hash {
    reads {
        ingress_metadata.ecmp_grp_id : exact;
    }
    actions {
        _nop;
        push_elenhop_id;
    }
    size : ECMP_GROUP_TABLE_SIZE;
}

/*
action set_ecmp_select(ecmp_grp_id, ecmp_grp_size) {
    modify_field(ingress_metadata.ecmp_grp_id, ecmp_grp_id);
    modify_field(ingress_metadata.ecmp_grp_size, ecmp_grp_size);
    modify_field_with_hash_based_offset(ingress_metadata.ecmp_nhop_id, 0,
                                        ecmp_hash, ecmp_grp_size);
    // why the 2nd and 4th parameter of modify_field_with_hash_based_offset
    // must be VAL ?
}
*/

table ecmp_nhop {
    reads {
        ingress_metadata.ecmp_grp_id : exact;
        ingress_metadata.ecmp_nhop_id : exact;
    }
    actions {
        _nop;
        set_nhop;
    }
    size : ECMP_NHOP_TABLE_SIZE;
}

/*
field_list resubmit_FL {
    //standard_metadata;
    ingress_metadata;
}
*/

action send_picked_elenhop_back() {
    add_header(flow_fingerprint);
    modify_field(flow_fingerprint.ipv4srcAddr, ipv4.srcAddr);
    modify_field(flow_fingerprint.ipv4dstAddr, ipv4.dstAddr);
    modify_field(flow_fingerprint.ipv4protocol, ipv4.protocol);
    modify_field(flow_fingerprint.tcpsrcPort, tcp.srcPort);
    modify_field(flow_fingerprint.tcpdstPort, tcp.dstPort);

    add_to_field(ipv4.totalLen, 13);

    add_header(udp);
    modify_field(udp.srcPort, FEEDBACK_PORT_NUM);
    modify_field(udp.dstPort, FEEDBACK_PORT_NUM);
    modify_field(udp.length_, ipv4.totalLen - 20 - (ipv4.fragOffset << 3) - (tcp.dataOffset << 2) + 8);
    modify_field(udp.checksum, 0);
    // This checksum field is optional in IPv4, and mandatory in IPv6,
    // which carries all-zeros if unused.

    add_to_field(ipv4.totalLen, 8);


    modify_field(ipv4.srcAddr, flow_fingerprint.ipv4dstAddr);
    modify_field(ipv4.dstAddr, flow_fingerprint.ipv4srcAddr);
    modify_field(ipv4.protocol, 17);
    modify_field(ipv4.ttl, 64);

    //modify_field(tcp.res, 0);
    remove_header(tcp);
    subtract_from_field(ipv4.totalLen, tcp.dataOffset << 2);

    modify_field(ingress_metadata.is_routed, 0);
    // let it be rerouted.
    //modify_field(ethernet.srcAddr, 0x111);
    //resubmit(resubmit_FL);
    // bmv2 does not support resubmit yet.

    modify_field(ingress_metadata.ether_srcAddr, ethernet.srcAddr);
    modify_field(ingress_metadata.ether_dstAddr, ethernet.dstAddr);

    modify_field(ethernet.srcAddr, 0x00aabb000001);
    modify_field(ethernet.dstAddr, ingress_metadata.ether_srcAddr);

}

table elepath_feedback {
    actions { send_picked_elenhop_back; }
}

action reset_header() {
    modify_field(tcp.res, 0);
}

table reset {
    actions { reset_header; }
}

control ingress {
    if (ipv4.protocol == IP_PROTOCOLS_TCP) {
        apply(default_ecmp_group);
        if (ingress_metadata.ecmp_grp_id != 0) {

            if (tcp.res == NORMAL_TCP) {
                apply(normal_ecmp_hash);
            } else if (tcp.res == ELEPATH_SETUP) {
                apply(robin_ele_hash);
            } else if (tcp.res == EXPLICIT_ELENHOP) {
                apply(fix_elenhop);
                if (elenhop_counter.val == 0) {
                    apply(clean_res_flag);
                }
            }

            apply(ecmp_nhop);
        }

        if (tcp.res == ELEPATH_SETUP){
            /*
            There is a weird "BUG" that, if not test whether (ipv4.protocol == IP_PROTOCOLS_TCP),
            the feedback UDP packet will also trigger a elepath_feedback.
            Maybe, this is because, the tcp.res value does not been rest at the beginning of this round.
            */
            apply(edge_check);
            if (ingress_metadata.is_edge_node == 1) {
                apply(elepath_feedback);
            }
        }
    } else {
        apply(reset);
    }

    if (ingress_metadata.is_routed == 0) {
        apply(default_route);
    }

    //apply(reset);
    // We use reset table to reset the value of tcp.res.
    // This is becasue, header fields will not be reseted/cleared automatically after a packet leaves.
    // Thus, for a non-TCP packet, when checking the value of tcp.res,
    // we will get that of the LAST TCP packet.
}

control egress {
}

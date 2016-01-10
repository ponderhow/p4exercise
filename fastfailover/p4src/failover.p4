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

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type failover_t {
    fields {
        flowID : 32;  // use dst IP as flowID in our tests
        pathID : 32;
    }
}

header ethernet_t ethernet;
header failover_t failover;
header ipv4_t ipv4;


header_type failover_metadata_t {
    fields {
        oldpathID : 32;
        spread_failover_msg : 1;
    }
}

header_type ipv4_metadata_t {
    fields{
        flowID: 32;
        pathID: 32;
    }
}

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 4;
        egress_rid : 4;
        mcast_hash : 16;
        lf_field_list: 32;
    }
}

metadata ipv4_metadata_t ipv4_metadata;
metadata failover_metadata_t failover_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x0101: parse_failover;
        0x0800: parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return ingress; // All done with parsing; start matching
}

parser parse_failover {
    extract(failover);
    return ingress;
}

register path_version_register {
    width: 32;
    instance_count: 16384;
    // indirect
}

register unused_path_version_register {
    width: 1;
    instance_count: 16384;
    // indirect
}

/*
http://mail.p4.org/pipermail/p4-dev_p4.org/2015-August/000098.html
Thanks for your interest. I will give more details inline. However the
basic answer to all your questions is that P4 registers are almost not
supported at all (yet) in the behavioral model software switch. Some
stateful operations are supported, but differe from what is in the spec.

On Wed, Aug 5, 2015 at 12:08 PM, Swaroop Thool <swaroopthool1991 at outlook.com
> wrote:

> Hi all ,
>
> Thanks for the answers. Few more questions:
> If I write-
>        register r {
>             width : 9;
>             static : table_which_invokes_register;
>             instance_count : 500;
>             attributes : saturating; }
>
> 1) If I create register array of 500(cells) as above, is it like 1-D array
> whose location can be read/write? How to access that because I am getting
> syntax error when I used modify_field(). What is the proper syntax if I
> want to put some value at run-time generated location of array, say 50?
>

You can do this, just not with modify_field(). You need to use
register_read() and register_write(), which are described here:
https://github.com/barefootnetworks/p4-hlir/blob/master/p4_hlir/frontend/primitives.json#L61
Something like this should work in an action:
register_read(*my_field*, r, 50);
add_to_field(*my_field*, 0xaba);
register_write(r, 50, *my_field*);
As you can see you can read / write a register, and once the value is in a
field, you can do arithmetic on it. However you cannot operate directly on
the register (for now).
*/

action update_flow_path() {
    //modify_field(failover_metadata.spread_failover_msg, unused_path_version_register[failover.pathID]);
    //modify_field(failover_metadata.oldpathID, path_version_register[failover.flowID]);
    //modify_field(unused_path_version_register[failover_metadata.oldpathID], 1);
    //modify_field(path_version_register[failover.flowID], failover.pathID);
    //modify_field(unused_path_version_register[failover.pathID], 0);

    register_read(failover_metadata.spread_failover_msg, unused_path_version_register, failover.pathID);
    register_read(failover_metadata.oldpathID, path_version_register, failover.flowID);
    register_write(unused_path_version_register, failover_metadata.oldpathID, 1);
    register_write(path_version_register, failover.flowID, failover.pathID);
    register_write(unused_path_version_register, failover.pathID, 0);
}

action set_path_id(flow_idx) {
    modify_field(ipv4_metadata.flowID, flow_idx);
    //modify_field(ipv4_metadata.pathID, path_version_register[flow_idx]);
    register_read(ipv4_metadata.pathID, path_version_register, flow_idx);
}

action multicast(mcast_grp) {
    modify_field(intrinsic_metadata.mcast_grp, mcast_grp);
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
    //add_to_field(ipv4.ttl, -1)
}

action _drop() {
    drop();
}

table failover_msg {
    actions {
        update_flow_path;
    }
    size: 1;
}

table flood_failover_msg {
    actions {
        multicast;
    }
    size: 1;
}

table ipv4_lookup {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions{
        set_path_id;
        _drop;
    }
    size: 1024;
}

table ipv4_fwd {
    reads {
        ipv4_metadata.pathID : exact;
    }
    actions {
        forward;
        _drop;
    }
    size: 1024;
}

control ingress {
    apply(ipv4_lookup);
    apply(ipv4_fwd);

    apply(failover_msg);
    if(failover_metadata.spread_failover_msg == 1){
        apply(flood_failover_msg);
    }
}

control egress {
}

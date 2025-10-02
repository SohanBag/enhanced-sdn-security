// advanced_ddos.p4
// BMv2 v1model - ARP Handling and Basic DDoS Filtering

#include <core.p4>
#include <v1model.p4>

// CPU port for controller communication
const bit<9> CPU_PORT = 255;

// ------------------------------
// Header definitions
// ------------------------------
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

// Header and metadata struct
struct headers {
    ethernet_t eth;
    ipv4_t     ip;
    tcp_t      tcp;
    udp_t      udp;
    arp_t      arp;
}
struct metadata {}

// ------------------------------
// Parser
// ------------------------------
parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t smeta) {
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }
    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_ipv4 {
        pkt.extract(hdr.ip);
        transition select(hdr.ip.protocol) {
            6:  parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// ------------------------------
// Checksum (no-op)
// ------------------------------
control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

// ------------------------------
// Ingress Logic
// ------------------------------
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t smeta) {

    action drop()           { mark_to_drop(smeta); }
    action punt_to_cpu()    { smeta.egress_spec = CPU_PORT; }
    action forward(bit<9> port) { smeta.egress_spec = port; }

    apply {
        // 1. Allow ARP for connectivity - for 3 hosts (ports 2, 3, 4)
        if (hdr.arp.isValid()) {
            if (smeta.ingress_port == 1) {
                forward(2); forward(3); return;
            } else if (smeta.ingress_port == 2) {
                forward(1); forward(3); return;
            } else if (smeta.ingress_port == 3) {
                forward(1); forward(2); return;
            } else {
                drop(); return;
            }
        }

        // 2. Drop SYN-only TCP floods (flags: SYN=1, ACK=0)
        if (hdr.tcp.isValid() && (hdr.tcp.flags & 0x12) == 0x02) {
            drop(); return;
        }

        // 3. Drop DNS amplification (UDP srcPort=53 & totalLen > 512)
        if (hdr.udp.isValid() &&
            hdr.udp.srcPort == 53 &&
            hdr.ip.totalLen  > 512) {
            drop(); return;
        }

        // 4. Punt all other IPv4 packets to controller (CPU port)
        if (hdr.ip.isValid()) {
            punt_to_cpu(); return;
        }

        // 5. Drop everything else (non-IPv4)
        drop();
    }
}

// ------------------------------
// Egress (no-op)
// ------------------------------
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t smeta) {
    apply { }
}

// ------------------------------
// Deparser
// ------------------------------
control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ip);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// ------------------------------
// Switch instantiation
// ------------------------------
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

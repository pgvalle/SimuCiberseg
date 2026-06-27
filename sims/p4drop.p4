/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define BMV2_V1MODEL_SPECIAL_DROP_PORT  511

const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> hw_type;
    bit<16> protocol_type;
    bit<8>  hw_size;
    bit<8>  protocol_size;
    bit<16> opcode;
    macAddr_t srcMac;
    ip4Addr_t srcIp;
    macAddr_t dstMac;
    ip4Addr_t dstIp;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<6>  res;
    bit<6>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP  : parse_arp;
            TYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6 : parse_tcp; // TCP = 6
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action mark_to_drop2(inout standard_metadata_t stdmata) {
        stdmata.egress_spec = BMV2_V1MODEL_SPECIAL_DROP_PORT;
        stdmata.mcast_grp = 0;
    }
    
    action drop() {
        mark_to_drop2(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_arp_nhop(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }

    table ipv4_nhop {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    table arp_simple {
        actions = {
            set_arp_nhop;
            drop;
        }
        key = {
            hdr.arp.dstIp: exact;
        }
        size = 1024;
    }

    // P4Drop parameters
    #define FLOW_TABLE_SIZE 65536
    #define DISTRUST_THRESHOLD_BLOCKED 5
    #define N_NORTX_THRESHOLD_LEGITIMATE 13 // 13 as determined by the paper experiments

    // Registers to store state
    register<bit<32>>(FLOW_TABLE_SIZE) reg_srcIP;
    register<bit<32>>(FLOW_TABLE_SIZE) reg_dstIP;
    register<bit<32>>(FLOW_TABLE_SIZE) reg_maxSeq;
    register<bit<32>>(FLOW_TABLE_SIZE) reg_gapStart;
    register<bit<14>>(FLOW_TABLE_SIZE) reg_gapLen;
    register<bit<5>>(FLOW_TABLE_SIZE) reg_n_noRTX;
    register<bit<1>>(FLOW_TABLE_SIZE) reg_hasDropped;
    // Paper specifics:
    register<bit<5>>(FLOW_TABLE_SIZE) reg_H1;
    register<bit<5>>(FLOW_TABLE_SIZE) reg_H2;
    register<bit<32>>(FLOW_TABLE_SIZE) reg_total_pkts;
    register<bit<5>>(FLOW_TABLE_SIZE) reg_dup_pkts;
    register<bit<32>>(FLOW_TABLE_SIZE) reg_last_seq;

    apply {
        if (hdr.arp.isValid()) {
            arp_simple.apply();
        } else if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
            // Drop all IP fragments (MF flag is bit 0 of flags)
            if (hdr.ipv4.fragOffset > 0 || (hdr.ipv4.flags & 1) == 1) {
                drop();
            } else if (hdr.tcp.isValid()) {
                // Compute TCP payload size
                bit<32> tcp_payload_len = (bit<32>)hdr.ipv4.totalLen - (bit<32>)(hdr.ipv4.ihl * 4) - (bit<32>)(hdr.tcp.dataOffset * 4);
                
                // Hash index calculation
                bit<32> hash_idx;
                hash(hash_idx, HashAlgorithm.crc32, (bit<32>)0, 
                     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort }, 
                     (bit<32>)FLOW_TABLE_SIZE);


                // Read register state
                bit<32> r_srcIP;
                bit<32> r_dstIP;
                bit<32> r_maxSeq;
                bit<32> r_gapStart;
                bit<14> r_gapLen;
                bit<5> r_n_noRTX;
                bit<1> r_hasDropped;
                bit<5> r_H1;
                bit<5> r_H2;
                bit<32> r_total_pkts;
                bit<5> r_dup_pkts;
                bit<32> r_last_seq;

                reg_srcIP.read(r_srcIP, hash_idx);
                reg_dstIP.read(r_dstIP, hash_idx);
                reg_maxSeq.read(r_maxSeq, hash_idx);
                reg_gapStart.read(r_gapStart, hash_idx);
                reg_gapLen.read(r_gapLen, hash_idx);
                reg_n_noRTX.read(r_n_noRTX, hash_idx);
                reg_hasDropped.read(r_hasDropped, hash_idx);
                reg_H1.read(r_H1, hash_idx);
                reg_H2.read(r_H2, hash_idx);
                reg_total_pkts.read(r_total_pkts, hash_idx);
                reg_dup_pkts.read(r_dup_pkts, hash_idx);
                reg_last_seq.read(r_last_seq, hash_idx);

                bit<1> is_new_flow = 0;
                if (r_srcIP != hdr.ipv4.srcAddr || r_dstIP != hdr.ipv4.dstAddr) {
                    is_new_flow = 1;
                }

                if (is_new_flow == 1) {
                    // New Flow detected: Save flow identifiers, mark hasDropped = 1
                    reg_srcIP.write(hash_idx, hdr.ipv4.srcAddr);
                    reg_dstIP.write(hash_idx, hdr.ipv4.dstAddr);
                    reg_maxSeq.write(hash_idx, hdr.tcp.seqNo);
                    reg_gapStart.write(hash_idx, hdr.tcp.seqNo);
                    reg_gapLen.write(hash_idx, (bit<14>)tcp_payload_len);
                    reg_n_noRTX.write(hash_idx, 0);
                    reg_hasDropped.write(hash_idx, 1);
                    reg_H1.write(hash_idx, 0);
                    reg_H2.write(hash_idx, 0);
                    reg_total_pkts.write(hash_idx, 1);
                    reg_dup_pkts.write(hash_idx, 0);
                    reg_last_seq.write(hash_idx, hdr.tcp.seqNo);
                    
                    // Trigger active drop
                    drop();
                } else {
                    bit<5> calculated_distrust;
                    if (r_H2 + 1 >= r_H1) {
                        calculated_distrust = (bit<5>)((r_H2 - r_H1) + 1);
                    } else {
                        calculated_distrust = 0; // Clamped to 0
                    }

                    if (calculated_distrust >= DISTRUST_THRESHOLD_BLOCKED) {
                        // Spoofer blocked!
                        drop();
                    } else {
                        // Update f_dup statistics
                        bit<32> next_total = r_total_pkts + 1;
                        bit<5> next_dup = r_dup_pkts;
                        if (hdr.tcp.seqNo == r_last_seq) {
                            next_dup = r_dup_pkts + 1;
                        }
                        reg_total_pkts.write(hash_idx, next_total);
                        reg_dup_pkts.write(hash_idx, next_dup);
                        reg_last_seq.write(hash_idx, hdr.tcp.seqNo);

                        // f_dup check: numerator * T2 >= denominator means high repetition rate (T2 = 7)
                        bit<32> threshold_check = (bit<32>)next_dup * 7;
                        if (threshold_check >= next_total && next_total > 10) {
                            // Penalty for excessive duplicates
                            r_H2 = r_H2 + 1;
                            reg_H2.write(hash_idx, r_H2);
                            reg_dup_pkts.write(hash_idx, 0);
                            reg_total_pkts.write(hash_idx, 1);
                        }

                        // Check if it's a retransmission of the actively dropped packet
                        if (hdr.tcp.seqNo == r_gapStart && (bit<14>)tcp_payload_len == r_gapLen && r_hasDropped == 1) {
                            // Legitimate flow retransmitted the dropped packet!
                            // Increase H1 (legitimate trust)
                            r_H1 = r_H1 + 1;
                            reg_H1.write(hash_idx, r_H1);
                            reg_n_noRTX.write(hash_idx, 0);
                            reg_hasDropped.write(hash_idx, 0); // Active drop test resolved
                            ipv4_nhop.apply();
                        } else {
                            if (hdr.tcp.seqNo > r_maxSeq) {
                                // New packet in the flow
                                reg_maxSeq.write(hash_idx, hdr.tcp.seqNo);
                                if (r_hasDropped == 1) {
                                    // Received another new packet while waiting for the retransmission of the dropped one.
                                    bit<5> next_n_noRTX = r_n_noRTX + 1;
                                    reg_n_noRTX.write(hash_idx, next_n_noRTX);
                                    if (next_n_noRTX >= N_NORTX_THRESHOLD_LEGITIMATE) {
                                        // Increase H2 (mistrust)
                                        r_H2 = r_H2 + 1;
                                        reg_H2.write(hash_idx, r_H2);
                                        // Reset n_noRTX
                                        reg_n_noRTX.write(hash_idx, 0);
                                    }
                                }
                            }
                            
                            // Re-calculate distrust dynamically after updates
                            if (r_H2 + 1 >= r_H1) {
                                calculated_distrust = (bit<5>)((r_H2 - r_H1) + 1);
                            } else {
                                calculated_distrust = 0;
                            }

                            // Probabilistic drop (5%) if in ambiguous state (distrust > 0)
                            if (calculated_distrust > 0) {
                                bit<8> rand_val;
                                random(rand_val, (bit<8>)0, (bit<8>)100);
                                if (rand_val < (bit<8>)5) {
                                    // Trigger active drop for sampling
                                    reg_gapStart.write(hash_idx, hdr.tcp.seqNo);
                                    reg_gapLen.write(hash_idx, (bit<14>)tcp_payload_len);
                                    reg_hasDropped.write(hash_idx, 1);
                                    drop();
                                } else {
                                    ipv4_nhop.apply();
                                }
                            } else {
                                ipv4_nhop.apply();
                            }
                        }
                    }
                }
            } else {
                // Non-TCP IPv4 packets, just forward
                ipv4_nhop.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
**********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
**********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

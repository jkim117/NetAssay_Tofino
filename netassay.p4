#include <core.p4>
#include <tna.p4>


#define NUM_KNOWN_DOMAINS 1024
#define NUM_KNOWN_DOMAINS_BITS 10
#define TABLE_SIZE 1024
#define HASH_TABLE_BASE 10w0
#define HASH_TABLE_MAX 10w1023
#define TIMEOUT 600000000 // 10 minutes



typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<32> known_domain_id;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> etherType; 
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    ipv4_addr_t src;
    ipv4_addr_t dst; 
}

header ipv6_h {
    bit<4> version;
    bit<8> tc;
    bit<20> fl;
    bit<16> plen;
    bit<8> nh;
    bit<8> hl;
    ipv6_addr_t src;
    ipv6_addr_t dst; 
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}

struct eg_metadata_t {
}

header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

header dns_q_label {
    bit<8> label;
}

header dns_q_part_1 {
    bit<8> part;
}

header dns_q_part_2 {
    bit<16> part;
}

header dns_q_part_4 {
    bit<32> part;
}

struct dns_qtype_class {
    bit<16> type;
    bit<16> class;
}

header dns_query_tc{
    dns_qtype_class tc_query;
}

header dns_a {
    bit<16> qname_pointer;
    dns_qtype_class tc_ans;
    bit<32> ttl;
    bit<16> rd_length;
}

header dns_a_ip {
    bit<32> rdata; //IPV4 is always 32 bit.
}

// List of all recognized hdr
struct header_t { 
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    dns_h dns_header;

    dns_q_label label1;
    dns_q_part_1 q1_part1;
    dns_q_part_2 q1_part2;
    dns_q_part_4 q1_part4;
    dns_q_part_4 q1_part8_1;
    dns_q_part_4 q1_part8_2;
    dns_q_part_4 q1_part16_1;
    dns_q_part_4 q1_part16_2;
    dns_q_part_4 q1_part16_3;
    dns_q_part_4 q1_part16_4;

    dns_q_label label2;
    dns_q_part_1 q2_part1;
    dns_q_part_2 q2_part2;
    dns_q_part_4 q2_part4;
    dns_q_part_4 q2_part8_1;
    dns_q_part_4 q2_part8_2;
    dns_q_part_4 q2_part16_1;
    dns_q_part_4 q2_part16_2;
    dns_q_part_4 q2_part16_3;
    dns_q_part_4 q2_part16_4;

    dns_q_label label3;
    dns_q_part_1 q3_part1;
    dns_q_part_2 q3_part2;
    dns_q_part_4 q3_part4;
    dns_q_part_4 q3_part8_1;
    dns_q_part_4 q3_part8_2;
    dns_q_part_4 q3_part16_1;
    dns_q_part_4 q3_part16_2;
    dns_q_part_4 q3_part16_3;
    dns_q_part_4 q3_part16_4;

    dns_q_label label4;
    dns_q_part_1 q4_part1;
    dns_q_part_2 q4_part2;
    dns_q_part_4 q4_part4;
    dns_q_part_4 q4_part8_1;
    dns_q_part_4 q4_part8_2;
    dns_q_part_4 q4_part16_1;
    dns_q_part_4 q4_part16_2;
    dns_q_part_4 q4_part16_3;
    dns_q_part_4 q4_part16_4;

    dns_q_label label5;
    dns_q_part_1 q5_part1;
    dns_q_part_2 q5_part2;
    dns_q_part_4 q5_part4;
    dns_q_part_4 q5_part8_1;
    dns_q_part_4 q5_part8_2;
    dns_q_part_4 q5_part16_1;
    dns_q_part_4 q5_part16_2;
    dns_q_part_4 q5_part16_3;
    dns_q_part_4 q5_part16_4;

    dns_q_label label6;

    dns_query_tc query_tc;

    dns_a dns_answer;
    dns_a_ip dns_ip;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct ig_metadata_t {
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
	bit<1> is_ip;
    bit<3>  unused;

    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
    bit<1> matched_domain;

    bit<32> q1_id;
    bit<32> q2_id;
    bit<32> q3_id;
    bit<32> q4_id;
    bit<32> domain_id;

    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;
    bit<32> temp_timestamp;
    bit<32> temp_cip;
    bit<32> temp_sip;
    bit<1> already_matched;
    bit<64> min_counter;
    bit<2> min_table;
    bit<32> temp_packet_counter;
    bit<32> temp_byte_counter;

    bit<32> temp_total_dns;
    bit<32> temp_total_missed;
    bit<1> parsed_answer;
}

struct sip_cip_t { 
    bit<32> sip;
    bit<32> cip;
}

struct domainid_timestamp_t { 
    bit<32> domain_id;
    bit<32> timestamp;
}

parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.advance(64); 
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition accept;
    }
}
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        // These are set appropriately in the TopPipe.
        ig_md.do_dns = 0;
        ig_md.recur_desired = 0;
        ig_md.response_set = 0;
		ig_md.is_dns = 0;
		ig_md.is_ip = 0;

        transition select(hdr.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(hdr.ipv4);

		ig_md.is_ip = 1;
        ig_md.is_dns = 0;
		transition select(hdr.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}

	state parse_udp {
        pkt.extract(hdr.udp);

		transition select(hdr.udp.dport) {
			53: parse_dns_header;
			default: parse_udp_2;
		}
	}

	state parse_udp_2 {
        //pkt.extract(hdr.udp);

		transition select(hdr.udp.sport) {
			53: parse_dns_header;
			default: accept;
        }
    }

	state parse_dns_header {
        pkt.extract(hdr.dns_header);
		ig_md.is_dns = 1;

        ig_md.last_label = 0;

        hdr.q5_part1.part = 0;
        hdr.q5_part2.part = 0;
        hdr.q5_part4.part = 0;
        hdr.q5_part8_1.part = 0;
        hdr.q5_part8_2.part = 0;
        hdr.q5_part16_1.part = 0;
        hdr.q5_part16_2.part = 0;
        hdr.q5_part16_3.part = 0;
        hdr.q5_part16_4.part = 0;

        hdr.q4_part1.part = 0;
        hdr.q4_part2.part = 0;
        hdr.q4_part4.part = 0;
        hdr.q4_part8_1.part = 0;
        hdr.q4_part8_2.part = 0;
        hdr.q4_part16_1.part = 0;
        hdr.q4_part16_2.part = 0;
        hdr.q4_part16_3.part = 0;
        hdr.q4_part16_4.part = 0;

        hdr.q3_part1.part = 0;
        hdr.q3_part2.part = 0;
        hdr.q3_part4.part = 0;
        hdr.q3_part8_1.part = 0;
        hdr.q3_part8_2.part = 0;
        hdr.q3_part16_1.part = 0;
        hdr.q3_part16_2.part = 0;
        hdr.q3_part16_3.part = 0;
        hdr.q3_part16_4.part = 0;

        hdr.q2_part1.part = 0;
        hdr.q2_part2.part = 0;
        hdr.q2_part4.part = 0;
        hdr.q2_part8_1.part = 0;
        hdr.q2_part8_2.part = 0;
        hdr.q2_part16_1.part = 0;
        hdr.q2_part16_2.part = 0;
        hdr.q2_part16_3.part = 0;
        hdr.q2_part16_4.part = 0;

        hdr.q1_part1.part = 0;
        hdr.q1_part2.part = 0;
        hdr.q1_part4.part = 0;
        hdr.q1_part8_1.part = 0;
        hdr.q1_part8_2.part = 0;
        hdr.q1_part16_1.part = 0;
        hdr.q1_part16_2.part = 0;
        hdr.q1_part16_3.part = 0;
        hdr.q1_part16_4.part = 0;

		transition select(hdr.dns_header.is_response) {
			1: parse_dns_query1;
			default: accept;
		}
	}

    // Parsel DNS Query Label 1
    state parse_dns_query1 {
        pkt.extract(hdr.label1);
        ig_md.last_label = 1;

        transition select(hdr.label1.label) {
            0: parse_query_tc;
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            8: parse_dns_q1_len8;
            9: parse_dns_q1_len9;
            10: parse_dns_q1_len10;
            11: parse_dns_q1_len11;
            12: parse_dns_q1_len12;
            13: parse_dns_q1_len13;
            14: parse_dns_q1_len14;
            15: parse_dns_q1_len15;
            16: parse_dns_q1_len16;
            17: parse_dns_q1_len17;
            18: parse_dns_q1_len18;
            19: parse_dns_q1_len19;
            20: parse_dns_q1_len20;
            21: parse_dns_q1_len21;
            22: parse_dns_q1_len22;
            23: parse_dns_q1_len23;
            24: parse_dns_q1_len24;
            25: parse_dns_q1_len25;
            26: parse_dns_q1_len26;
            27: parse_dns_q1_len27;
            28: parse_dns_q1_len28;
            29: parse_dns_q1_len29;
            30: parse_dns_q1_len30;
            31: parse_dns_q1_len31;
            default: accept;
        }
    }

    state parse_dns_q1_len1 {
        pkt.extract(hdr.q1_part1);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len2 {
        pkt.extract(hdr.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len3 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len4 {
        pkt.extract(hdr.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len5 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len6 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len7 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len8 {
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len9 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len10 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len11 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len12 {
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len13 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len14 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len15 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len16 {
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len17 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len18 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len19 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len20 {
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len21 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len22 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len23 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len24 {
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len25 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len26 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len27 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len28 {
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len29 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len30 {
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len31 {
        pkt.extract(hdr.q1_part1);
        pkt.extract(hdr.q1_part2);
        pkt.extract(hdr.q1_part4);
        pkt.extract(hdr.q1_part8_1);
        pkt.extract(hdr.q1_part8_2);
        pkt.extract(hdr.q1_part16_1);
        pkt.extract(hdr.q1_part16_2);
        pkt.extract(hdr.q1_part16_3);
        pkt.extract(hdr.q1_part16_4);
        transition parse_dns_query2;
    }

    // Parsel DNS Query Label 2
    state parse_dns_query2 {
        pkt.extract(hdr.label2);
        ig_md.last_label = 2;

        transition select(hdr.label2.label) {
            0: parse_query_tc;
            1: parse_dns_q2_len1;
            2: parse_dns_q2_len2;
            3: parse_dns_q2_len3;
            4: parse_dns_q2_len4;
            5: parse_dns_q2_len5;
            6: parse_dns_q2_len6;
            7: parse_dns_q2_len7;
            8: parse_dns_q2_len8;
            9: parse_dns_q2_len9;
            10: parse_dns_q2_len10;
            11: parse_dns_q2_len11;
            12: parse_dns_q2_len12;
            13: parse_dns_q2_len13;
            14: parse_dns_q2_len14;
            15: parse_dns_q2_len15;
            16: parse_dns_q2_len16;
            17: parse_dns_q2_len17;
            18: parse_dns_q2_len18;
            19: parse_dns_q2_len19;
            20: parse_dns_q2_len20;
            21: parse_dns_q2_len21;
            22: parse_dns_q2_len22;
            23: parse_dns_q2_len23;
            24: parse_dns_q2_len24;
            25: parse_dns_q2_len25;
            26: parse_dns_q2_len26;
            27: parse_dns_q2_len27;
            28: parse_dns_q2_len28;
            29: parse_dns_q2_len29;
            30: parse_dns_q2_len30;
            31: parse_dns_q2_len31;
            default: accept;
        }
    }

    state parse_dns_q2_len1 {
        pkt.extract(hdr.q2_part1);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len2 {
        pkt.extract(hdr.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len3 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len4 {
        pkt.extract(hdr.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len5 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len6 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len7 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len8 {
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len9 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len10 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len11 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len12 {
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len13 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len14 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len15 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len16 {
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len17 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len18 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len19 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len20 {
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len21 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len22 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len23 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len24 {
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len25 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len26 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len27 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len28 {
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len29 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len30 {
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len31 {
        pkt.extract(hdr.q2_part1);
        pkt.extract(hdr.q2_part2);
        pkt.extract(hdr.q2_part4);
        pkt.extract(hdr.q2_part8_1);
        pkt.extract(hdr.q2_part8_2);
        pkt.extract(hdr.q2_part16_1);
        pkt.extract(hdr.q2_part16_2);
        pkt.extract(hdr.q2_part16_3);
        pkt.extract(hdr.q2_part16_4);
        transition parse_dns_query3;
    }

    
    // Parsel DNS Query Label 3
    state parse_dns_query3 {
        pkt.extract(hdr.label3);
        ig_md.last_label = 3;

        transition select(hdr.label3.label) {
            0: parse_query_tc;
            1: parse_dns_q3_len1;
            2: parse_dns_q3_len2;
            3: parse_dns_q3_len3;
            4: parse_dns_q3_len4;
            5: parse_dns_q3_len5;
            6: parse_dns_q3_len6;
            7: parse_dns_q3_len7;
            8: parse_dns_q3_len8;
            9: parse_dns_q3_len9;
            10: parse_dns_q3_len10;
            11: parse_dns_q3_len11;
            12: parse_dns_q3_len12;
            13: parse_dns_q3_len13;
            14: parse_dns_q3_len14;
            15: parse_dns_q3_len15;
            16: parse_dns_q3_len16;
            17: parse_dns_q3_len17;
            18: parse_dns_q3_len18;
            19: parse_dns_q3_len19;
            20: parse_dns_q3_len20;
            21: parse_dns_q3_len21;
            22: parse_dns_q3_len22;
            23: parse_dns_q3_len23;
            24: parse_dns_q3_len24;
            25: parse_dns_q3_len25;
            26: parse_dns_q3_len26;
            27: parse_dns_q3_len27;
            28: parse_dns_q3_len28;
            29: parse_dns_q3_len29;
            30: parse_dns_q3_len30;
            31: parse_dns_q3_len31;
            default: accept;
        }
    }

    state parse_dns_q3_len1 {
        pkt.extract(hdr.q3_part1);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len2 {
        pkt.extract(hdr.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len3 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len4 {
        pkt.extract(hdr.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len5 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len6 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len7 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len8 {
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len9 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len10 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len11 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len12 {
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len13 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len14 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len15 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len16 {
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len17 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len18 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len19 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len20 {
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len21 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len22 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len23 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len24 {
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len25 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len26 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len27 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len28 {
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len29 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len30 {
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len31 {
        pkt.extract(hdr.q3_part1);
        pkt.extract(hdr.q3_part2);
        pkt.extract(hdr.q3_part4);
        pkt.extract(hdr.q3_part8_1);
        pkt.extract(hdr.q3_part8_2);
        pkt.extract(hdr.q3_part16_1);
        pkt.extract(hdr.q3_part16_2);
        pkt.extract(hdr.q3_part16_3);
        pkt.extract(hdr.q3_part16_4);
        transition parse_dns_query4;
    }

    
    // Parsel DNS Query Label 4
    state parse_dns_query4 {
        pkt.extract(hdr.label4);
        ig_md.last_label = 4;

        transition select(hdr.label4.label) {
            0: parse_query_tc;
            1: parse_dns_q4_len1;
            2: parse_dns_q4_len2;
            3: parse_dns_q4_len3;
            4: parse_dns_q4_len4;
            5: parse_dns_q4_len5;
            6: parse_dns_q4_len6;
            7: parse_dns_q4_len7;
            8: parse_dns_q4_len8;
            9: parse_dns_q4_len9;
            10: parse_dns_q4_len10;
            11: parse_dns_q4_len11;
            12: parse_dns_q4_len12;
            13: parse_dns_q4_len13;
            14: parse_dns_q4_len14;
            15: parse_dns_q4_len15;
            16: parse_dns_q4_len16;
            17: parse_dns_q4_len17;
            18: parse_dns_q4_len18;
            19: parse_dns_q4_len19;
            20: parse_dns_q4_len20;
            21: parse_dns_q4_len21;
            22: parse_dns_q4_len22;
            23: parse_dns_q4_len23;
            24: parse_dns_q4_len24;
            25: parse_dns_q4_len25;
            26: parse_dns_q4_len26;
            27: parse_dns_q4_len27;
            28: parse_dns_q4_len28;
            29: parse_dns_q4_len29;
            30: parse_dns_q4_len30;
            31: parse_dns_q4_len31;
            default: accept;
        }
    }

    state parse_dns_q4_len1 {
        pkt.extract(hdr.q4_part1);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len2 {
        pkt.extract(hdr.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len3 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len4 {
        pkt.extract(hdr.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len5 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len6 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len7 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len8 {
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len9 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len10 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len11 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len12 {
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len13 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len14 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len15 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len16 {
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len17 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len18 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len19 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len20 {
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len21 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len22 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len23 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len24 {
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len25 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len26 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len27 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len28 {
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len29 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len30 {
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len31 {
        pkt.extract(hdr.q4_part1);
        pkt.extract(hdr.q4_part2);
        pkt.extract(hdr.q4_part4);
        pkt.extract(hdr.q4_part8_1);
        pkt.extract(hdr.q4_part8_2);
        pkt.extract(hdr.q4_part16_1);
        pkt.extract(hdr.q4_part16_2);
        pkt.extract(hdr.q4_part16_3);
        pkt.extract(hdr.q4_part16_4);
        transition parse_dns_query5;
    }

    // Parsel DNS Query Label 5
    state parse_dns_query5 {
        pkt.extract(hdr.label5);
        ig_md.last_label = 5;

        transition select(hdr.label5.label) {
            0: parse_query_tc;
            1: parse_dns_q5_len1;
            2: parse_dns_q5_len2;
            3: parse_dns_q5_len3;
            4: parse_dns_q5_len4;
            5: parse_dns_q5_len5;
            6: parse_dns_q5_len6;
            7: parse_dns_q5_len7;
            8: parse_dns_q5_len8;
            9: parse_dns_q5_len9;
            10: parse_dns_q5_len10;
            11: parse_dns_q5_len11;
            12: parse_dns_q5_len12;
            13: parse_dns_q5_len13;
            14: parse_dns_q5_len14;
            15: parse_dns_q5_len15;
            16: parse_dns_q5_len16;
            17: parse_dns_q5_len17;
            18: parse_dns_q5_len18;
            19: parse_dns_q5_len19;
            20: parse_dns_q5_len20;
            21: parse_dns_q5_len21;
            22: parse_dns_q5_len22;
            23: parse_dns_q5_len23;
            24: parse_dns_q5_len24;
            25: parse_dns_q5_len25;
            26: parse_dns_q5_len26;
            27: parse_dns_q5_len27;
            28: parse_dns_q5_len28;
            29: parse_dns_q5_len29;
            30: parse_dns_q5_len30;
            31: parse_dns_q5_len31;
            default: accept;
        }
    }

    state parse_dns_q5_len1 {
        pkt.extract(hdr.q5_part1);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len2 {
        pkt.extract(hdr.q5_part2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len3 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len4 {
        pkt.extract(hdr.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len5 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len6 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len7 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len8 {
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len9 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len10 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len11 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len12 {
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len13 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len14 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len15 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len16 {
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len17 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len18 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len19 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len20 {
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len21 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len22 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len23 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len24 {
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len25 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len26 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len27 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len28 {
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len29 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len30 {
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len31 {
        pkt.extract(hdr.q5_part1);
        pkt.extract(hdr.q5_part2);
        pkt.extract(hdr.q5_part4);
        pkt.extract(hdr.q5_part8_1);
        pkt.extract(hdr.q5_part8_2);
        pkt.extract(hdr.q5_part16_1);
        pkt.extract(hdr.q5_part16_2);
        pkt.extract(hdr.q5_part16_3);
        pkt.extract(hdr.q5_part16_4);
        transition parse_dns_query6;
    }


    // Parsel DNS Query Label 6
    state parse_dns_query6 {
        pkt.extract(hdr.label6);
        ig_md.last_label = 6;

        transition select(hdr.label6.label) {
            0: parse_query_tc;
            default: accept;
        }
    }

    state parse_query_tc {
        pkt.extract(hdr.query_tc);
        ig_md.parsed_answer = 0;
        transition parse_dns_answer;
    }

    state parse_dns_answer {
        pkt.extract(hdr.dns_answer);

        transition select(hdr.dns_answer.tc_ans.type) {
            1: parse_a_ip;
            5: parse_cname;
            default: accept;
        }
    }

    state parse_cname {
        //pkt.advance((bit<32>)(8 * hdr.dns_answer.rd_length));//TODO

        transition parse_dns_answer;
    }

    state parse_a_ip {
        pkt.extract(hdr.dns_ip);
        ig_md.parsed_answer = 1;

        transition accept;
    }








}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
         
    Resubmit() resubmit;
    
    apply {        

        if (ig_intr_dprsr_md.resubmit_type == 1) {
            //resubmit.emit(ig_md.resubmit_data_write);
            resubmit.emit();
        }
 
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        //pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
         

    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }
    action nop() {
    }
    action reflect(){
        //send you back to where you're from
        ig_intr_tm_md.ucast_egress_port=ig_intr_md.ingress_port;
    }
    action route_to_64(){
        //route to CPU NIC. on model, it is veth250
        ig_intr_tm_md.ucast_egress_port=64;
    }

    // joon.
    Register<bit<32>,_>(TABLE_SIZE,0) ipv4_dst_rdata_table;
    RegisterAction<bit<32>,_,void> (ipv4_dst_rdata_table) ipv4_dst_rdata_table_reg_write_action = {
        void apply(inout bit<32> ipv4_dst) {
            ipv4_dst = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_rdata_table) ipv4_dst_rdata_table_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> rdata_bigger) {
            if (hdr.dns_ip.rdata > ipv4_dst) {
                rdata_bigger = 1;
            }
            else {
                rdata_bigger = 0;
            }
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) ipv4_dst_ipv4src_table;
    RegisterAction<bit<32>,_,void> (ipv4_dst_ipv4src_table) ipv4_dst_ipv4src_table_reg_write_action = {
        void apply(inout bit<32> ipv4_dst) {
            ipv4_dst = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_ipv4src_table) ipv4_dst_ipv4src_table_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> ipv4src_bigger) {
            if (hdr.ipv4.src > ipv4_dst) {
                ipv4src_bigger = 1;
            }
            else {
                ipv4src_bigger = 0;
            }
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) ipv4_dst_cip_table_1;
    RegisterAction<bit<32>,_,void> (ipv4_dst_cip_table_1) ipv4_dst_cip_table_1_reg_write_action = {
        void apply(inout bit<32> ipv4_dst) {
            ipv4_dst = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_cip_table_1) ipv4_dst_cip_table_1_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> match_cip) {
            if (ig_md.temp_cip == ipv4_dst) {
                match_cip = 1;
            }
            else {
                match_cip = 0;
            }
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) ipv4_dst_cip_table_2;
    RegisterAction<bit<32>,_,void> (ipv4_dst_cip_table_2) ipv4_dst_cip_table_2_reg_write_action = {
        void apply(inout bit<32> ipv4_dst) {
            ipv4_dst = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_cip_table_2) ipv4_dst_cip_table_2_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> match_cip) {
            if (ig_md.temp_cip == ipv4_dst) {
                match_cip = 1;
            }
            else {
                match_cip = 0;
            }
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) ipv4_dst_cip_table_3;
    RegisterAction<bit<32>,_,void> (ipv4_dst_cip_table_3) ipv4_dst_cip_table_3_reg_write_action = {
        void apply(inout bit<32> ipv4_dst) {
            ipv4_dst = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_cip_table_3) ipv4_dst_cip_table_3_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> match_cip) {
            if (ig_md.temp_cip == ipv4_dst) {
                match_cip = 1;
            }
            else {
                match_cip = 0;
            }
        }
    };
 
//    Register<bit<32>,_>(TABLE_SIZE,0) global_tstamp_table_1;
//    RegisterAction<bit<32>,_,void> (global_tstamp_table_1) globaltstamp_table_1_reg_write_action = {
//        void apply(inout bit<32> global_tstamp) {
//            global_tstamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
//        }
//    };
//    RegisterAction<bit<32>,_,bit<1>> (global_tstamp_table_1) globaltstamp_table_1_reg_compare_temptstamp_action = {
//        void apply(inout bit<32> global_tstamp, out bit<1> timedout) {
//            if (ig_md.temp_timestamp + TIMEOUT < global_tstamp) {
//                timedout = 1;
//            }
//            else {
//                timedout = 0;
//            }
//        }
//    };
//
//    Register<bit<32>,_>(TABLE_SIZE,0) global_tstamp_table_2;
//    RegisterAction<bit<32>,_,void> (global_tstamp_table_2) globaltstamp_table_2_reg_write_action = {
//        void apply(inout bit<32> global_tstamp) {
//            global_tstamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
//        }
//    };
//    RegisterAction<bit<32>,_,bit<1>> (global_tstamp_table_2) globaltstamp_table_2_reg_compare_temptstamp_action = {
//        void apply(inout bit<32> global_tstamp, out bit<1> timedout) {
//            if (ig_md.temp_timestamp + TIMEOUT < global_tstamp) {
//                timedout = 1;
//            }
//            else {
//                timedout = 0;
//            }
//        }
//    };
//
//    Register<bit<32>,_>(TABLE_SIZE,0) global_tstamp_table_3;
//    RegisterAction<bit<32>,_,void> (global_tstamp_table_3) globaltstamp_table_3_reg_write_action = {
//        void apply(inout bit<32> global_tstamp) {
//            global_tstamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
//        }
//    };
//    RegisterAction<bit<32>,_,bit<1>> (global_tstamp_table_3) globaltstamp_table_3_reg_compare_temptstamp_action = {
//        void apply(inout bit<32> global_tstamp, out bit<1> timedout) {
//            if (ig_md.temp_timestamp + TIMEOUT < global_tstamp) {
//                timedout = 1;
//            }
//            else {
//                timedout = 0;
//            }
//        }
//    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_ip_rdata_table_1;
    RegisterAction<bit<32>,_,void> (dns_ip_rdata_table_1) dns_ip_rdata_table_1_reg_write_action = {
        void apply(inout bit<32> dns_ip_rdata) {
            dns_ip_rdata = hdr.dns_ip.rdata;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_ip_rdata_table_1) dns_ip_rdata_table_1_reg_compare_sip_action = {
        void apply(inout bit<32> dns_ip_rdata, out bit<1> match_sip) {
            if (ig_md.temp_sip == dns_ip_rdata) {
                match_sip = 1;
            }
            else {
                match_sip = 0;
            }
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_ip_rdata_table_2;
    RegisterAction<bit<32>,_,void> (dns_ip_rdata_table_2) dns_ip_rdata_table_2_reg_write_action = {
        void apply(inout bit<32> dns_ip_rdata) {
            dns_ip_rdata = hdr.dns_ip.rdata;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_ip_rdata_table_2) dns_ip_rdata_table_2_reg_compare_sip_action = {
        void apply(inout bit<32> dns_ip_rdata, out bit<1> match_sip) {
            if (ig_md.temp_sip == dns_ip_rdata) {
                match_sip = 1;
            }
            else {
                match_sip = 0;
            }
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_ip_rdata_table_3;
    RegisterAction<bit<32>,_,void> (dns_ip_rdata_table_3) dns_ip_rdata_table_3_reg_write_action = {
        void apply(inout bit<32> dns_ip_rdata) {
            dns_ip_rdata = hdr.dns_ip.rdata;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_ip_rdata_table_3) dns_ip_rdata_table_3_reg_compare_sip_action = {
        void apply(inout bit<32> dns_ip_rdata, out bit<1> match_sip) {
            if (ig_md.temp_sip == dns_ip_rdata) {
                match_sip = 1;
            }
            else {
                match_sip = 0;
            }
        }
    };


    // PRECISION STYLE TABLES
    //register<bit<32>>(TABLE_SIZE) dns_cip_table_1;
    //register<bit<32>>(TABLE_SIZE) dns_sip_table_1;
    //register<bit<32>>(TABLE_SIZE) dns_name_table_1;
    //register<bit<32>>(TABLE_SIZE) dns_timestamp_table_1;

    //NOTE: not sure how to set initial value for paired elements. Same for reg_2 and reg_3.
    Register<sip_cip_t,_>(TABLE_SIZE) sip_cip_reg_1; 
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_1) sip_cip_reg_1_check_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            if (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_1) sip_cip_reg_1_check_bidir_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            //if ( (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) || (value.sip == hdr.ipv4.dst && value.cip == hdr.dns_ip.rdata) ) {
            if (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) {
                is_match = 1;
            }
            else if (value.sip == hdr.ipv4.dst && value.cip == hdr.dns_ip.rdata) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<sip_cip_t,_,void> (sip_cip_reg_1) sip_cip_reg_1_update_action = {
        void apply(inout sip_cip_t value) {
            value.sip = hdr.dns_ip.rdata;
            value.cip = hdr.ipv4.dst;
        }
    };

    //NOTE: not sure how to set initial value for paired elements. Same for reg_2 and reg_3.
    Register<domainid_timestamp_t,_>(TABLE_SIZE) domain_tstamp_reg_1;
    RegisterAction<domainid_timestamp_t,_,bit<1>> (domain_tstamp_reg_1) domain_tstamp_reg_1_check_tstamp_action = {
        void apply(inout domainid_timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<domainid_timestamp_t,_,bit<32>> (domain_tstamp_reg_1) domain_tstamp_reg_1_get_domain_and_update_ts_action = {
        void apply(inout domainid_timestamp_t value, out bit<32> domain_id) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            domain_id = value.domain_id;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_1) domain_tstamp_reg_1_update_tstamp_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_1) domain_tstamp_reg_1_update_tstamp_domain_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            value.domain_id = ig_md.domain_id;
        }
    };

    Register<sip_cip_t,_>(TABLE_SIZE) sip_cip_reg_2;
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_2) sip_cip_reg_2_check_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            if (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_2) sip_cip_reg_2_check_bidir_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            //if ( (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) || (value.sip == hdr.ipv4.dst && value.cip == hdr.dns_ip.rdata) ) {
            //    is_match = 1;
            //}
            //else {
            //    is_match = 0;
            //}
            if (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) {
                is_match = 1;
            }
            else if (value.sip == hdr.ipv4.dst && value.cip == hdr.dns_ip.rdata) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }

        }
    };
    RegisterAction<sip_cip_t,_,void> (sip_cip_reg_2) sip_cip_reg_2_update_action = {
        void apply(inout sip_cip_t value) {
            value.sip = hdr.dns_ip.rdata;
            value.cip = hdr.ipv4.dst;
        }
    };

    Register<domainid_timestamp_t,_>(TABLE_SIZE) domain_tstamp_reg_2;
    RegisterAction<domainid_timestamp_t,_,bit<1>> (domain_tstamp_reg_2) domain_tstamp_reg_2_check_tstamp_action = {
        void apply(inout domainid_timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<domainid_timestamp_t,_,bit<32>> (domain_tstamp_reg_2) domain_tstamp_reg_2_get_domain_and_update_ts_action = {
        void apply(inout domainid_timestamp_t value, out bit<32> domain_id) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            domain_id = value.domain_id;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_2) domain_tstamp_reg_2_update_tstamp_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_2) domain_tstamp_reg_2_update_tstamp_domain_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            value.domain_id = ig_md.domain_id;
        }
    };

    Register<sip_cip_t,_>(TABLE_SIZE) sip_cip_reg_3;
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_3) sip_cip_reg_3_check_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            if (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_3) sip_cip_reg_3_check_bidir_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            //if ( (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) || (value.sip == hdr.ipv4.dst && value.cip == hdr.dns_ip.rdata) ) {
            //    is_match = 1;
            //}
            //else {
            //    is_match = 0;
            //}
            if (value.sip == hdr.dns_ip.rdata && value.cip == hdr.ipv4.dst) {
                is_match = 1;
            }
            else if (value.sip == hdr.ipv4.dst && value.cip == hdr.dns_ip.rdata) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }

        }
    };
    RegisterAction<sip_cip_t,_,void> (sip_cip_reg_3) sip_cip_reg_3_update_action = {
        void apply(inout sip_cip_t value) {
            value.sip = hdr.dns_ip.rdata;
            value.cip = hdr.ipv4.dst;
        }
    };

    Register<domainid_timestamp_t,_>(TABLE_SIZE) domain_tstamp_reg_3;
    RegisterAction<domainid_timestamp_t,_,bit<1>> (domain_tstamp_reg_3) domain_tstamp_reg_3_check_tstamp_action = {
        void apply(inout domainid_timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<domainid_timestamp_t,_,bit<32>> (domain_tstamp_reg_3) domain_tstamp_reg_3_get_domain_and_update_ts_action = {
        void apply(inout domainid_timestamp_t value, out bit<32> domain_id) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            domain_id = value.domain_id;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_3) domain_tstamp_reg_3_update_tstamp_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_3) domain_tstamp_reg_3_update_tstamp_domain_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            value.domain_id = ig_md.domain_id;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_cip_table_1;
    RegisterAction<bit<32>,_,bit<32>> (dns_cip_table_1) dns_cip_table_1_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_1) dns_cip_table_1_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_1) dns_cip_table_1_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = hdr.dns_ip.rdata;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_sip_table_1;
    RegisterAction<bit<32>,_,bit<32>> (dns_sip_table_1) dns_sip_table_1_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_1) dns_sip_table_1_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_1) dns_sip_table_1_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = hdr.dns_ip.rdata;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_name_table_1;
    RegisterAction<bit<32>,_,bit<32>> (dns_name_table_1) dns_name_table_1_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_name_table_1) dns_name_table_1_reg_write_domainid_action = {
        void apply(inout bit<32> value) {
            value = ig_md.domain_id;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_timestamp_table_1;
    RegisterAction<bit<32>,_,bit<32>> (dns_timestamp_table_1) dns_timestamp_table_1_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_timestamp_table_1) dns_timestamp_table_1_reg_write_tstamp_action = {
        void apply(inout bit<32> value) {
            value = (bit<32>) ig_intr_prsr_md.global_tstamp;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_cip_table_2;
    RegisterAction<bit<32>,_,bit<32>> (dns_cip_table_2) dns_cip_table_2_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_2) dns_cip_table_2_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_2) dns_cip_table_2_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = hdr.dns_ip.rdata;
        }
    };
 
    Register<bit<32>,_>(TABLE_SIZE,0) dns_sip_table_2;
    RegisterAction<bit<32>,_,bit<32>> (dns_sip_table_2) dns_sip_table_2_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_2) dns_sip_table_2_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_2) dns_sip_table_2_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = hdr.dns_ip.rdata;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_name_table_2;
    RegisterAction<bit<32>,_,bit<32>> (dns_name_table_2) dns_name_table_2_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_name_table_2) dns_name_table_2_reg_write_domainid_action = {
        void apply(inout bit<32> value) {
            value = ig_md.domain_id;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_timestamp_table_2;
    RegisterAction<bit<32>,_,bit<32>> (dns_timestamp_table_2) dns_timestamp_table_2_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_timestamp_table_2) dns_timestamp_table_2_reg_write_tstamp_action = {
        void apply(inout bit<32> value) {
            value = (bit<32>) ig_intr_prsr_md.global_tstamp;
        }
    };
 
    Register<bit<32>,_>(TABLE_SIZE,0) dns_cip_table_3;
    RegisterAction<bit<32>,_,bit<32>> (dns_cip_table_3) dns_cip_table_3_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_3) dns_cip_table_3_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_3) dns_cip_table_3_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = hdr.dns_ip.rdata;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_sip_table_3;
    RegisterAction<bit<32>,_,bit<32>> (dns_sip_table_3) dns_sip_table_3_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_3) dns_sip_table_3_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = hdr.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_3) dns_sip_table_3_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = hdr.dns_ip.rdata;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_name_table_3;
    RegisterAction<bit<32>,_,bit<32>> (dns_name_table_3) dns_name_table_3_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_name_table_3) dns_name_table_3_reg_write_domainid_action = {
        void apply(inout bit<32> value) {
            value = ig_md.domain_id;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_timestamp_table_3;
    RegisterAction<bit<32>,_,bit<32>> (dns_timestamp_table_3) dns_timestamp_table_3_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_timestamp_table_3) dns_timestamp_table_3_reg_write_tstamp_action = {
        void apply(inout bit<32> value) {
            value = (bit<32>) ig_intr_prsr_md.global_tstamp;
        }
    };
 
    // REGISTER ARRAY FOR COLLECTING COUNTS ON TRAFFIC WITH KNOWN DOMAINS
    //register<bit<32>>(NUM_KNOWN_DOMAINS) packet_counts_table;
    //register<bit<32>>(NUM_KNOWN_DOMAINS) byte_counts_table;
    Register<bit<32>,_>(NUM_KNOWN_DOMAINS) packet_counts_table;
    RegisterAction<bit<32>,_,void> (packet_counts_table) packet_counts_table_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };

    Register<bit<64>,_>(NUM_KNOWN_DOMAINS) byte_counts_table;
    RegisterAction<bit<32>,_,bit<32>> (byte_counts_table) byte_counts_table_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (byte_counts_table) byte_counts_table_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + (bit<32>)hdr.ipv4.len;
        }
    };

    // REGISTER ARRAY FOR KEEPING TRACK OF OVERFLOW DNS RESPONSES
    //register<bit<32>>(NUM_KNOWN_DOMAINS) dns_total_queried;
    //register<bit<32>>(NUM_KNOWN_DOMAINS) dns_total_missed;
    Register<bit<32>,_>(NUM_KNOWN_DOMAINS) dns_total_queried;
    RegisterAction<bit<32>,_, void> (dns_total_queried) dns_total_queried_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };
 
    Register<bit<32>,_>(NUM_KNOWN_DOMAINS) dns_total_missed;
    RegisterAction<bit<32>,_, void> (dns_total_missed) dns_total_missed_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };

    action match_q1(known_domain_id q1id) {
        ig_md.q1_id = q1id;
    }

    action match_q2(known_domain_id q2id) {
        ig_md.q2_id = q2id;
    }

    action match_q3(known_domain_id q3id) {
        ig_md.q3_id = q3id;
    }

    action match_q4(known_domain_id q4id) {
        ig_md.q4_id = q4id;
    }

    action match_domain(known_domain_id id) {
        ig_md.domain_id = id;
        ig_md.matched_domain = 1;
    }

    table known_domain_list_q1 {
        key = {
            hdr.q1_part1.part: ternary;
            hdr.q1_part2.part: ternary;
            hdr.q1_part4.part: ternary;
            hdr.q1_part8_1.part: ternary;
            hdr.q1_part8_2.part: ternary;
            hdr.q1_part16_1.part: ternary;
            hdr.q1_part16_2.part: ternary;
            hdr.q1_part16_3.part: ternary;
            hdr.q1_part16_4.part: ternary;
        }

        actions = {
            match_q1;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table known_domain_list_q2 {
        key = {
            hdr.q2_part1.part: ternary;
            hdr.q2_part2.part: ternary;
            hdr.q2_part4.part: ternary;
            hdr.q2_part8_1.part: ternary;
            hdr.q2_part8_2.part: ternary;
            hdr.q2_part16_1.part: ternary;
            hdr.q2_part16_2.part: ternary;
            hdr.q2_part16_3.part: ternary;
            hdr.q2_part16_4.part: ternary;
            ig_md.q1_id: ternary;
        }

        actions = {
            match_q2;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table known_domain_list_q3 {
        key = {
            hdr.q3_part1.part: ternary;
            hdr.q3_part2.part: ternary;
            hdr.q3_part4.part: ternary;
            hdr.q3_part8_1.part: ternary;
            hdr.q3_part8_2.part: ternary;
            hdr.q3_part16_1.part: ternary;
            hdr.q3_part16_2.part: ternary;
            hdr.q3_part16_3.part: ternary;
            hdr.q3_part16_4.part: ternary;
            ig_md.q2_id: ternary;
        }

        actions = {
            match_q3;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table known_domain_list_q4 {
        key = {
            hdr.q4_part1.part: ternary;
            hdr.q4_part2.part: ternary;
            hdr.q4_part4.part: ternary;
            hdr.q4_part8_1.part: ternary;
            hdr.q4_part8_2.part: ternary;
            hdr.q4_part16_1.part: ternary;
            hdr.q4_part16_2.part: ternary;
            hdr.q4_part16_3.part: ternary;
            hdr.q4_part16_4.part: ternary;
            ig_md.q3_id: ternary;
        }

        actions = {
            match_q4;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table known_domain_list_q5 {
        key = {
            hdr.q5_part1.part: ternary;
            hdr.q5_part2.part: ternary;
            hdr.q5_part4.part: ternary;
            hdr.q5_part8_1.part: ternary;
            hdr.q5_part8_2.part: ternary;
            hdr.q5_part16_1.part: ternary;
            hdr.q5_part16_2.part: ternary;
            hdr.q5_part16_3.part: ternary;
            hdr.q5_part16_4.part: ternary;
            ig_md.q4_id: ternary;
        }

        actions = {
            match_domain;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    apply {

        ig_md.already_matched = 0;
        bool is_resubmitted=(bool) ig_intr_md.resubmit_flag;

        if(ig_md.parsed_answer == 1) { // If DNS packet with parsed response.
            ig_md.q1_id = 0;
            ig_md.q2_id = 0;
            ig_md.q3_id = 0;
            ig_md.q4_id = 0;
            ig_md.domain_id = 0;
            ig_md.matched_domain = 0;

            // initialize
            ig_md.temp_cip = 0;
            ig_md.temp_sip = 0;
            ig_md.temp_timestamp = 0;
            bit<1> rdata_bigger = 0;
            bit<1> ipv4src_bigger = 0;
            bit<1> match_but_timedout = 0;
            bit<1> match_cip = 0;
            bit<1> match_sip = 0;

            known_domain_list_q1.apply();
            known_domain_list_q2.apply();
            known_domain_list_q3.apply();
            known_domain_list_q4.apply();
            known_domain_list_q5.apply();

            if (ig_md.matched_domain == 1) {

                // Increment total DNS queries for this domain name
                //dns_total_queried.read(ig_md.temp_total_dns, ig_md.domain_id);
                //dns_total_queried.write(ig_md.domain_id, ig_md.temp_total_dns + 1);

                dns_total_queried_reg_inc_action.execute(ig_md.domain_id);

                /*
                rdata_bigger = ipv4_dst_rdata_table_reg_compare_action.execute(1);
                if (rdata_bigger == 1) {
                //if (hdr.dns_ip.rdata > hdr.ipv4.dst) { //TODO
                    //hash(ig_md.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {hdr.dns_ip.rdata, 7w11, hdr.ipv4.dst}, HASH_TABLE_MAX);
                    //hash(ig_md.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, hdr.dns_ip.rdata, 5w3, hdr.ipv4.dst}, HASH_TABLE_MAX);
                    //hash(ig_md.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, hdr.dns_ip.rdata, 1w1, hdr.ipv4.dst}, HASH_TABLE_MAX);
                    ig_md.index_1 = (bit<32>) hash_1.get({hdr.dns_ip.rdata, 7w11, hdr.ipv4.dst});
                    ig_md.index_2 = (bit<32>) hash_1.get({3w5, hdr.dns_ip.rdata, 5w3, hdr.ipv4.dst});
                    ig_md.index_3 = (bit<32>) hash_1.get({2w0, hdr.dns_ip.rdata, 1w1, hdr.ipv4.dst});
                }
                else {
                    //hash(ig_md.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {hdr.ipv4.dst, 7w11, hdr.dns_ip.rdata}, HASH_TABLE_MAX);
                    //hash(ig_md.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, hdr.ipv4.dst, 5w3, hdr.dns_ip.rdata}, HASH_TABLE_MAX);
                    //hash(ig_md.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, hdr.ipv4.dst, 1w1, hdr.dns_ip.rdata}, HASH_TABLE_MAX);
                    ig_md.index_1 = (bit<32>) hash_1.get({hdr.ipv4.dst, 7w11, hdr.dns_ip.rdata});
                    ig_md.index_2 = (bit<32>) hash_1.get({3w5, hdr.ipv4.dst, 5w3, hdr.dns_ip.rdata});
                    ig_md.index_3 = (bit<32>) hash_1.get({2w0, hdr.ipv4.dst, 1w1, hdr.dns_ip.rdata});
                }
                */

                // hdr.dns_ip.rdata is sip and hdr.ipv4.dst is cip. So sip followed by cip when hashing
                ig_md.index_1 = (bit<32>) hash_1.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w134140211);
                ig_md.index_2 = (bit<32>) hash_1.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w187182238);
                ig_md.index_3 = (bit<32>) hash_1.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w232108253);

                // access table 1
                if (!is_resubmitted) {

                    //dns_cip_table_1.read(ig_md.temp_cip, ig_md.index_1);
                    //dns_sip_table_1.read(ig_md.temp_sip, ig_md.index_1);
                    //dns_timestamp_table_1.read(ig_md.temp_timestamp, ig_md.index_1);

                    // Read sip_cip table
                    bit<1> is_match =  sip_cip_reg_1_check_action.execute(ig_md.index_1);
                    
                    // If sip and cip matches, just update timestamp
                    if (is_match == 1) {
                        domain_tstamp_reg_1_update_tstamp_action.execute(ig_md.index_1);
                        ig_md.already_matched = 1;
                    }
                    else { 
                        // Check timestamp
                        bit<1> timed_out = domain_tstamp_reg_1_check_tstamp_action.execute(ig_md.index_1);

                        // If entry timed out, replace entry. For this, resubmit packet.
                        if (timed_out == 1) {
                            // Set resubmit
                            ig_intr_dprsr_md.resubmit_type = 1;
                        }

                        // Else, we have a collision that we cannot replace reg_1. 
                        // Continue to reg_2.
                    }
                }
                // Resubmitted packet. That means this is for updating entry in reg_1.
                else {
                    sip_cip_reg_1_update_action.execute(ig_md.index_1);
                    domain_tstamp_reg_1_update_tstamp_domain_action.execute(ig_md.index_1);
                    ig_md.already_matched = 1;
                }

                /*
                ig_md.temp_cip = dns_cip_table_1_reg_read_action.execute(ig_md.index_1);
                ig_md.temp_sip = dns_sip_table_1_reg_read_action.execute(ig_md.index_1);
                ig_md.temp_timestamp = dns_timestamp_table_1_reg_read_action.execute(ig_md.index_1); 

                // if no match, or matchtimestamp is over timeout, or matchcip and matchsip matches header (i.e., not a collision)
                //   - refresh register and say it is matched.

                match_but_timedout = globaltstamp_table_1_reg_compare_temptstamp_action.execute(1);
                match_cip = ipv4_dst_cip_table_1_reg_compare_action.execute(1);
                match_sip = dns_ip_rdata_table_1_reg_compare_sip_action.execute(1);

                if (match_cip == 1 && match_sip == 1) {
                    dns_timestamp_table_1_reg_write_tstamp_action.execute(ig_md.index_1);
                    dns_name_table_1_reg_write_domainid_action.execute(ig_md.index_1);

                    ig_md.already_matched = 1;
                }
                else if () {


                }

                //if (ig_md.temp_timestamp == 0 || ig_md.temp_timestamp + TIMEOUT < (bit<32>) ig_intr_prsr_md.global_tstamp || (ig_md.temp_cip == hdr.ipv4.dst && ig_md.temp_sip == hdr.dns_ip.rdata)) {
                if (ig_md.temp_timestamp == 0 || match_but_timedout== 1 || (match_cip == 1 && match_sip == 1)) {
                    //dns_cip_table_1.write(ig_md.index_1, hdr.ipv4.dst);
                    //dns_sip_table_1.write(ig_md.index_1, hdr.dns_ip.rdata);
                    //dns_timestamp_table_1.write(ig_md.index_1, (bit<32>)ig_intr_prsr_md.global_tstamp);
                    //dns_name_table_1.write(ig_md.index_1, ig_md.domain_id);

                    dns_cip_table_1_reg_write_ipv4dst_action.execute(ig_md.index_1);
                    dns_sip_table_1_reg_write_dnsiprdata_action.execute(ig_md.index_1);
                    dns_timestamp_table_1_reg_write_tstamp_action.execute(ig_md.index_1);
                    dns_name_table_1_reg_write_domainid_action.execute(ig_md.index_1);

                    ig_md.already_matched = 1;
                }
                */

                // access table 2
                if (ig_md.already_matched == 0) {
                    // Not resubmitted packet. Then check things. 
                    if (!is_resubmitted) {
                        // Read sip_cip table
                        bit<1> is_match =  sip_cip_reg_2_check_action.execute(ig_md.index_2);
                        
                        // If sip and cip matches, just update timestamp
                        if (is_match == 1) {
                            domain_tstamp_reg_2_update_tstamp_action.execute(ig_md.index_2);
                            ig_md.already_matched = 1;
                        }
                        else { 
                            // Check timestamp
                            bit<1> timed_out = domain_tstamp_reg_2_check_tstamp_action.execute(ig_md.index_2);

                            // If entry timed out, replace entry. For this, resubmit packet.
                            if (timed_out == 1) {
                                // Set resubmit
                                ig_intr_dprsr_md.resubmit_type = 1;
                            }

                            // Else, we have a collision that we cannot replace reg_2.
                            // Continue to reg_3.
                        }
                    }
                    // Resubmitted packet. That means this is for updating entry in reg_2.
                    else {
                        sip_cip_reg_2_update_action.execute(ig_md.index_2);
                        domain_tstamp_reg_2_update_tstamp_domain_action.execute(ig_md.index_2);
                        ig_md.already_matched = 1;
                    }

                    /*
                    //dns_cip_table_2.read(ig_md.temp_cip, ig_md.index_2);
                    //dns_sip_table_2.read(ig_md.temp_sip, ig_md.index_2);
                    //dns_timestamp_table_2.read(ig_md.temp_timestamp, ig_md.index_2);

                    ig_md.temp_cip = dns_cip_table_2_reg_read_action.execute(ig_md.index_2);
                    ig_md.temp_sip = dns_sip_table_2_reg_read_action.execute(ig_md.index_2);
                    ig_md.temp_timestamp = dns_timestamp_table_2_reg_read_action.execute(ig_md.index_2);

                    if (ig_md.temp_timestamp == 0 || ig_md.temp_timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp || (ig_md.temp_cip == hdr.ipv4.dst && ig_md.temp_sip == hdr.dns_ip.rdata)) {
                        //dns_cip_table_2.write(ig_md.index_2, hdr.ipv4.dst);
                        //dns_sip_table_2.write(ig_md.index_2, hdr.dns_ip.rdata);
                        //dns_timestamp_table_2.write(ig_md.index_2, (bit<32>)ig_intr_prsr_md.global_tstamp);
                        //dns_name_table_2.write(ig_md.index_2, ig_md.domain_id);

                        dns_cip_table_2_reg_write_ipv4dst_action.execute(ig_md.index_2);
                        dns_sip_table_2_reg_write_dnsiprdata_action.execute(ig_md.index_2);
                        dns_timestamp_table_2_reg_write_tstamp_action.execute(ig_md.index_2);
                        dns_name_table_2_reg_write_domainid_action.execute(ig_md.index_2);

                        ig_md.already_matched = 1;
                    }
                    */
                }

                // access table 3
                if (ig_md.already_matched == 0) {

                    // Not resubmitted packet. Then check things. 
                    if (!is_resubmitted) {
                        // Read sip_cip table
                        bit<1> is_match =  sip_cip_reg_3_check_action.execute(ig_md.index_3);
                        
                        // If sip and cip matches, just update timestamp
                        if (is_match == 1) {
                            domain_tstamp_reg_3_update_tstamp_action.execute(ig_md.index_3);
                            ig_md.already_matched = 1;
                        }
                        else { 
                            // Check timestamp
                            bit<1> timed_out = domain_tstamp_reg_3_check_tstamp_action.execute(ig_md.index_3);

                            // If entry timed out, replace entry. For this, resubmit packet.
                            if (timed_out == 1) {
                                // Set resubmit
                                ig_intr_dprsr_md.resubmit_type = 1;
                            }

                            // Else, we have a collision that we cannot replace reg_3.
                            // Continue to reg_3.
                        }
                    }
                    // Resubmitted packet. That means this is for updating entry in reg_3.
                    else {
                        sip_cip_reg_3_update_action.execute(ig_md.index_3);
                        domain_tstamp_reg_3_update_tstamp_domain_action.execute(ig_md.index_3);
                        ig_md.already_matched = 1;
                    }

                    /*
                    //dns_cip_table_3.read(ig_md.temp_cip, ig_md.index_3);
                    //dns_sip_table_3.read(ig_md.temp_sip, ig_md.index_3);
                    //dns_timestamp_table_3.read(ig_md.temp_timestamp, ig_md.index_3);

                    ig_md.temp_cip = dns_cip_table_3_reg_read_action.execute(ig_md.index_3);
                    ig_md.temp_sip = dns_sip_table_3_reg_read_action.execute(ig_md.index_3);
                    ig_md.temp_timestamp = dns_timestamp_table_3_reg_read_action.execute(ig_md.index_3);

                    match_but_timedout = globaltstamp_table_3_reg_compare_temptstamp_action.execute(1);
                    match_cip = ipv4_dst_cip_table_3_reg_compare_action.execute(1);
                    match_sip = dns_ip_rdata_table_3_reg_compare_sip_action.execute(1);

                    //if (ig_md.temp_timestamp == 0 || ig_md.temp_timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp || (ig_md.temp_cip == hdr.ipv4.dst && ig_md.temp_sip == hdr.dns_ip.rdata)) {
                    if (ig_md.temp_timestamp == 0 || match_but_timedout== 1 || (match_cip == 1 && match_sip == 1)) {
                        //dns_cip_table_3.write(ig_md.index_3, hdr.ipv4.dst);
                        //dns_sip_table_3.write(ig_md.index_3, hdr.dns_ip.rdata);
                        //dns_timestamp_table_3.write(ig_md.index_3, (bit<32>)ig_intr_prsr_md.global_tstamp);
                        //dns_name_table_3.write(ig_md.index_3, ig_md.domain_id);

                        dns_cip_table_3_reg_write_ipv4dst_action.execute(ig_md.index_3);
                        dns_sip_table_3_reg_write_dnsiprdata_action.execute(ig_md.index_3);
                        dns_timestamp_table_3_reg_write_tstamp_action.execute(ig_md.index_3);
                        dns_name_table_3_reg_write_domainid_action.execute(ig_md.index_3);

                        ig_md.already_matched = 1;
                    }
                    */
                }

                // No match until reaching reg_3. missed!
                if (ig_md.already_matched == 0) {
                    // Increment total DNS queries missed for this domain name
                    //dns_total_missed.read(ig_md.temp_total_missed, ig_md.domain_id);
                    //dns_total_missed.write(ig_md.domain_id, ig_md.temp_total_missed + 1);

                    dns_total_missed_reg_inc_action.execute(ig_md.domain_id);
                }
            }
        }
        // HANDLE NORMAL, NON-DNS PACKETS
        else if (ig_md.is_ip == 1 && ig_md.is_dns == 0) {

            /*
            bit<1> ipv4src_bigger = 0;
            ipv4src_bigger = ipv4_dst_ipv4src_table_reg_compare_action.execute(1);
            if (ipv4src_bigger == 1) { //TODO
            //if (hdr.ipv4.src > hdr.ipv4.dst) {
                //hash(ig_md.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {hdr.ipv4.src, 7w11, hdr.ipv4.dst}, HASH_TABLE_MAX);
                //hash(ig_md.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, hdr.ipv4.src, 5w3, hdr.ipv4.dst}, HASH_TABLE_MAX);
                //hash(ig_md.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, hdr.ipv4.src, 1w1, hdr.ipv4.dst}, HASH_TABLE_MAX);

                ig_md.index_1 = (bit<32>) hash_1.get({hdr.ipv4.src, 7w11, hdr.ipv4.dst});
                ig_md.index_2 = (bit<32>) hash_1.get({3w5, hdr.ipv4.src, 5w3, hdr.ipv4.dst});
                ig_md.index_3 = (bit<32>) hash_1.get({2w0, hdr.ipv4.src, 1w1, hdr.ipv4.dst});
            }
            else {
                //hash(ig_md.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {hdr.ipv4.dst, 7w11, hdr.ipv4.src}, HASH_TABLE_MAX);
                //hash(ig_md.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, hdr.ipv4.dst, 5w3, hdr.ipv4.src}, HASH_TABLE_MAX);
                //hash(ig_md.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, hdr.ipv4.dst, 1w1, hdr.ipv4.src}, HASH_TABLE_MAX);

                ig_md.index_1 = (bit<32>) hash_1.get({hdr.ipv4.dst, 7w11, hdr.ipv4.src});
                ig_md.index_2 = (bit<32>) hash_1.get({3w5, hdr.ipv4.dst, 5w3, hdr.ipv4.src});
                ig_md.index_3 = (bit<32>) hash_1.get({2w0, hdr.ipv4.dst, 1w1, hdr.ipv4.src});
            }
            */
            //dns_cip_table_1.read(ig_md.temp_cip, ig_md.index_1);
            //dns_sip_table_1.read(ig_md.temp_sip, ig_md.index_1);

            //ig_md.temp_cip = dns_cip_table_1_reg_read_action.execute(ig_md.index_1);
            //ig_md.temp_sip = dns_sip_table_1_reg_read_action.execute(ig_md.index_1);

            // Assume hdr.ipv4.dst is sip and hdr.ipv4.src is cip. So sip followed by cip when hashing
            ig_md.index_1 = (bit<32>) hash_1.get(headers.ipv4.src + headers.ipv4.dst + 32w134140211);
            ig_md.index_2 = (bit<32>) hash_1.get(headers.ipv4.src + headers.ipv4.dst + 32w187182238);
            ig_md.index_3 = (bit<32>) hash_1.get(headers.ipv4.src + headers.ipv4.dst + 32w232108253);

            bit<1> sip_cip_matched = 0;
            bit<32> index_for_update = 0;
            ig_md.already_matched = 0;

            // register_1
            sip_cip_matched = sip_cip_reg_1_check_action.execute(ig_md.index_1); //TODO:should be bidirectional check
            if (sip_cip_matched == 1) {
                // Get domain_id and udpate timestamp
                ig_md.domain_id = domain_tstamp_reg_1_get_domain_and_update_ts_action.execute(ig_md.index_1);

                // Update packet_count, update byte_count
                //packet_counts_table_reg_inc_action.execute(ig_md.index_1);
                //byte_counts_table_reg_inc_action.execute(ig_md.index_1);
                index_for_update = ig_md.index_1;
                ig_md.already_matched = 1;
            }

            // register_2
            if (ig_md.already_matched == 0) {
                sip_cip_matched = sip_cip_reg_2_check_action.execute(ig_md.index_2); //TODO
                if (sip_cip_matched == 1) {
                    // Get domain_id and udpate timestamp
                    ig_md.domain_id = domain_tstamp_reg_2_get_domain_and_update_ts_action.execute(ig_md.index_2);

                    // Update packet_count, update byte_count
                    //packet_counts_table_reg_inc_action.execute(ig_md.index_2);
                    //byte_counts_table_reg_inc_action.execute(ig_md.index_2);
                    index_for_update = ig_md.index_2;
                    ig_md.already_matched = 1;
                }
            }

            // register_3
            if (ig_md.already_matched == 0) {
                sip_cip_matched = sip_cip_reg_3_check_action.execute(ig_md.index_3); //TODO
                if (sip_cip_matched == 1) {
                    // Get domain_id and udpate timestamp
                    ig_md.domain_id = domain_tstamp_reg_3_get_domain_and_update_ts_action.execute(ig_md.index_3);

                    // Update packet_count, update byte_count
                    //packet_counts_table_reg_inc_action.execute(ig_md.index_3);
                    //byte_counts_table_reg_inc_action.execute(ig_md.index_3);
                    index_for_update = ig_md.index_3;
                    ig_md.already_matched = 1;
                }
            }

            if (ig_md.already_matched == 1) {
                packet_counts_table_reg_inc_action.execute(index_for_update);
                byte_counts_table_reg_inc_action.execute(index_for_update);
            }

            /* //TODO
            if ((hdr.ipv4.dst == ig_md.temp_cip && hdr.ipv4.src == ig_md.temp_sip) || (hdr.ipv4.dst == ig_md.temp_sip && hdr.ipv4.src == ig_md.temp_cip)) {//TODO
                //dns_name_table_1.read(ig_md.domain_id, ig_md.index_1);
                //packet_counts_table.read(ig_md.temp_packet_counter, ig_md.domain_id);
                //byte_counts_table.read(ig_md.temp_byte_counter, ig_md.domain_id);
                //packet_counts_table.write(ig_md.domain_id, ig_md.temp_packet_counter + 1);
                //byte_counts_table.write(ig_md.domain_id, ig_md.temp_byte_counter + (bit<32>)hdr.ipv4.len);
                //dns_timestamp_table_1.write(ig_md.index_1, (bit<32>)ig_intr_prsr_md.global_tstamp);

                ig_md.domain_id = dns_name_table_1_reg_read_action.execute(ig_md.index_1);
                packet_counts_table_reg_inc_action.execute(ig_md.domain_id);
                byte_counts_table_reg_inc_action.execute(ig_md.domain_id);
                dns_timestamp_table_1_reg_write_tstamp_action.execute(ig_md.index_1);
 
            }

            //dns_cip_table_2.read(ig_md.temp_cip, ig_md.index_2);
            //dns_sip_table_2.read(ig_md.temp_sip, ig_md.index_2);
            ig_md.temp_cip = dns_cip_table_2_reg_read_action.execute(ig_md.index_2);
            ig_md.temp_sip = dns_sip_table_2_reg_read_action.execute(ig_md.index_2);
 
            if ((hdr.ipv4.dst == ig_md.temp_cip && hdr.ipv4.src == ig_md.temp_sip) || (hdr.ipv4.dst == ig_md.temp_sip && hdr.ipv4.src == ig_md.temp_cip)) { //TODO
                //dns_name_table_2.read(ig_md.domain_id, ig_md.index_2);
                //packet_counts_table.read(ig_md.temp_packet_counter, ig_md.domain_id);
                //byte_counts_table.read(ig_md.temp_byte_counter, ig_md.domain_id);
                //packet_counts_table.write(ig_md.domain_id, ig_md.temp_packet_counter + 1);
                //byte_counts_table.write(ig_md.domain_id, ig_md.temp_byte_counter + (bit<32>)hdr.ipv4.len);
                //dns_timestamp_table_2.write(ig_md.index_2, (bit<32>)ig_intr_prsr_md.global_tstamp);

                ig_md.domain_id = dns_name_table_2_reg_read_action.execute(ig_md.index_2);
                packet_counts_table_reg_inc_action.execute(ig_md.domain_id);
                byte_counts_table_reg_inc_action.execute(ig_md.domain_id);
                dns_timestamp_table_2_reg_write_tstamp_action.execute(ig_md.index_2);
            }

            //dns_cip_table_3.read(ig_md.temp_cip, ig_md.index_3);
            //dns_sip_table_3.read(ig_md.temp_sip, ig_md.index_3);
            ig_md.temp_cip = dns_cip_table_3_reg_read_action.execute(ig_md.index_3);
            ig_md.temp_sip = dns_sip_table_3_reg_read_action.execute(ig_md.index_3);
 
            if ((hdr.ipv4.dst == ig_md.temp_cip && hdr.ipv4.src == ig_md.temp_sip) || (hdr.ipv4.dst == ig_md.temp_sip && hdr.ipv4.src == ig_md.temp_cip)) { //TODO
                //dns_name_table_3.read(ig_md.domain_id, ig_md.index_3);
                //packet_counts_table.read(ig_md.temp_packet_counter, ig_md.domain_id);
                //byte_counts_table.read(ig_md.temp_byte_counter, ig_md.domain_id);
                //packet_counts_table.write(ig_md.domain_id, ig_md.temp_packet_counter + 1);
                //byte_counts_table.write(ig_md.domain_id, ig_md.temp_byte_counter + (bit<32>)hdr.ipv4.len);
                //dns_timestamp_table_3.write(ig_md.index_3, (bit<32>)ig_intr_prsr_md.global_tstamp);

                ig_md.domain_id = dns_name_table_3_reg_read_action.execute(ig_md.index_3);
                packet_counts_table_reg_inc_action.execute(ig_md.domain_id);
                byte_counts_table_reg_inc_action.execute(ig_md.domain_id);
                dns_timestamp_table_3_reg_write_tstamp_action.execute(ig_md.index_3);
            }
            */
        }
	}
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;

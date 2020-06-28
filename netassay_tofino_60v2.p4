#include <core.p4>
#include <tna.p4>

#define NUM_BANNED_DST_IP 100
#define NUM_ALLOWABLE_DST_IP 100
#define NUM_KNOWN_DOMAINS 2048
#define NUM_KNOWN_DOMAINS_BITS 10
#define TABLE_SIZE 16384
#define HASH_TABLE_BASE 14w0
#define HASH_TABLE_MAX 14w16383
#define TIMEOUT 300000000 // 5 minutes

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<32> known_domain_id;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
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
    IPv4Address src;
    IPv4Address dst; 
}
header ipv6_h {
    bit<4> version;
    bit<8> tc;
    bit<20> fl;
    bit<16> plen;
    bit<8> nh;
    bit<8> hl;
    IPv6Address src;
    IPv6Address dst; 
}
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
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
    bit<8> rd_length_1;
    bit<8> rd_length_2;
}

header dns_a_ip {
    bit<32> rdata; //IPV4 is always 32 bit.
}

// List of all recognized headers
struct Parsed_packet { 
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

    dns_q_label label2;
    dns_q_part_1 q2_part1;
    dns_q_part_2 q2_part2;
    dns_q_part_4 q2_part4;
    dns_q_part_4 q2_part8_1;
    dns_q_part_4 q2_part8_2;

    dns_q_label label3;
    dns_q_part_1 q3_part1;
    dns_q_part_2 q3_part2;
    dns_q_part_4 q3_part4;
    dns_q_part_4 q3_part8_1;
    dns_q_part_4 q3_part8_2;

    dns_q_label label4;
    dns_q_part_1 q4_part1;
    dns_q_part_2 q4_part2;
    dns_q_part_4 q4_part4;
    dns_q_part_4 q4_part8_1;
    dns_q_part_4 q4_part8_2;

    dns_q_label label5;

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
    bit<32> domain_id;
    bit<32> index_1_dns;
    bit<32> index_2_dns;
    bit<32> index_3_dns;
    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;
    bit<48> temp_timestamp;
    bit<32> temp_cip;
    bit<32> temp_sip;
    bit<1> already_matched;
    bit<64> min_counter;
    bit<2> min_table;
    bit<64> temp_packet_counter;
    bit<64> temp_byte_counter;

    bit<64> temp_total_dns;
    bit<64> temp_total_missed;
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

struct eg_metadata_t {
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

// parsers
parser SwitchIngressParser(packet_in pkt,
           out Parsed_packet p,
           out ig_metadata_t ig_md,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    ParserCounter() counter;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
        ig_md.do_dns = 0;
        ig_md.recur_desired = 0;
        ig_md.response_set = 0;
		ig_md.is_dns = 0;
		ig_md.is_ip = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		ig_md.is_ip = 1;
        ig_md.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}

    state parse_udp {
        pkt.extract(p.udp);

		transition select(p.udp.dport) {
			53: parse_dns_header;
			default: parse_udp_2;
		}
	}

	state parse_udp_2 {

		transition select(p.udp.sport) {
			53: parse_dns_header;
			default: accept;
        }
    }

	state parse_dns_header {
        pkt.extract(p.dns_header);
		ig_md.is_dns = 1;

        ig_md.last_label = 0;

        p.q4_part1.part = 0;
        p.q4_part2.part = 0;
        p.q4_part4.part = 0;
        p.q4_part8_1.part = 0;
        p.q4_part8_2.part = 0;

        p.q3_part1.part = 0;
        p.q3_part2.part = 0;
        p.q3_part4.part = 0;
        p.q3_part8_1.part = 0;
        p.q3_part8_2.part = 0;

        p.q2_part1.part = 0;
        p.q2_part2.part = 0;
        p.q2_part4.part = 0;
        p.q2_part8_1.part = 0;
        p.q2_part8_2.part = 0;

        p.q1_part1.part = 0;
        p.q1_part2.part = 0;
        p.q1_part4.part = 0;
        p.q1_part8_1.part = 0;
        p.q1_part8_2.part = 0;

		transition select(p.dns_header.is_response) {
			1: parse_dns_query1;
			default: accept;
		}
	}

    // Parsel DNS Query Label 1
    state parse_dns_query1 {
        pkt.extract(p.label1);
        ig_md.last_label = 1;

        transition select(p.label1.label) {
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
            default: accept;
        }
    }

    state parse_dns_q1_len1 {
        pkt.extract(p.q1_part1);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len2 {
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len3 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len4 {
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len5 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len6 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len8 {
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len9 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len10 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len11 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len12 {
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len13 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len14 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len15 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    // Parsel DNS Query Label 2
    state parse_dns_query2 {
        pkt.extract(p.label2);
        ig_md.last_label = 2;

        transition select(p.label2.label) {
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
            default: accept;
        }
    }

    state parse_dns_q2_len1 {
        pkt.extract(p.q2_part1);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len2 {
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len3 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len4 {
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len5 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len6 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len7 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len8 {
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len9 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len10 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len11 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len12 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len13 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len14 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len15 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    
    // Parsel DNS Query Label 3
    state parse_dns_query3 {
        pkt.extract(p.label3);
        ig_md.last_label = 3;

        transition select(p.label3.label) {
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
            default: accept;
        }
    }

    state parse_dns_q3_len1 {
        pkt.extract(p.q3_part1);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len2 {
        pkt.extract(p.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len3 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len4 {
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len5 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len6 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len7 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len8 {
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len9 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len10 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len11 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len12 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len13 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len14 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len15 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    
    // Parsel DNS Query Label 4
    state parse_dns_query4 {
        pkt.extract(p.label4);
        ig_md.last_label = 4;

        transition select(p.label4.label) {
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
            default: accept;
        }
    }

    state parse_dns_q4_len1 {
        pkt.extract(p.q4_part1);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len2 {
        pkt.extract(p.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len3 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len4 {
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len5 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len6 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len7 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len8 {
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len9 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len10 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len11 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len12 {
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len13 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len14 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len15 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }


    // Parsel DNS Query Label 5
    state parse_dns_query5 {
        pkt.extract(p.label5);
        ig_md.last_label = 5;

        transition select(p.label5.label) {
            0: parse_query_tc;
            default: accept;
        }
    }

    state parse_query_tc {
        pkt.extract(p.query_tc);
        ig_md.parsed_answer = 0;
        transition parse_dns_answer;
    }

    state parse_dns_answer {
        pkt.extract(p.dns_answer);

        transition select(p.dns_answer.tc_ans.type) {
            1: parse_a_ip;
            5: parse_cname;
            default: accept;
        }
    }

    state parse_cname {
        counter.set(p.dns_answer.rd_length_2);

        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    state parse_cname_byte{
        pkt.advance(8);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    state parse_a_ip {
        pkt.extract(p.dns_ip);
        ig_md.parsed_answer = 1;

        transition accept;
    }
}
/**************************END OF PARSER**************************/

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout Parsed_packet hdr,
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
        out Parsed_packet hdr,
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
        inout Parsed_packet hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}

// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(inout Parsed_packet headers,
                inout ig_metadata_t ig_md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    Register<bit<32>,_>(TABLE_SIZE,0) ipv4_dst_rdata_table;
    RegisterAction<bit<32>,_,void> (ipv4_dst_rdata_table) ipv4_dst_rdata_table_reg_write_action = {
        void apply(inout bit<32> ipv4_dst) {
            ipv4_dst = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_rdata_table) ipv4_dst_rdata_table_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> rdata_bigger) {
            if (headers.dns_ip.rdata > ipv4_dst) {
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
            ipv4_dst = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (ipv4_dst_ipv4src_table) ipv4_dst_ipv4src_table_reg_compare_action = {
        void apply(inout bit<32> ipv4_dst, out bit<1> ipv4src_bigger) {
            if (headers.ipv4.src > ipv4_dst) {
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
            ipv4_dst = headers.ipv4.dst;
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
            ipv4_dst = headers.ipv4.dst;
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
            ipv4_dst = headers.ipv4.dst;
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
            dns_ip_rdata = headers.dns_ip.rdata;
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
            dns_ip_rdata = headers.dns_ip.rdata;
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
            dns_ip_rdata = headers.dns_ip.rdata;
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
    Register<bit<32>,_>(TABLE_SIZE) dns_cip_reg_1; 
    RegisterAction<bit<32>,_,bit<1>> (dns_cip_reg_1) dns_cip_reg_1_check_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            if (value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_cip_reg_1) dns_cip_reg_1_check_bidir_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            //if ( (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) || (value.sip == headers.ipv4.dst && value.cip == headers.dns_ip.rdata) ) {

            if (value == headers.ipv4.src || value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_reg_1) dns_cip_reg_1_update_action = {
        void apply(inout bit<32> value) {
            value = headers.ipv4.dst;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE) dns_sip_reg_1; 
    RegisterAction<bit<32>,_,bit<1>> (dns_sip_reg_1) dns_sip_reg_1_check_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            if (value == headers.dns_ip.rdata) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_sip_reg_1) dns_sip_reg_1_check_bidir_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            //if ( (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) || (value.sip == headers.ipv4.dst && value.cip == headers.dns_ip.rdata) ) {

            if (value == headers.ipv4.src || value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_reg_1) dns_sip_reg_1_update_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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

    // Register 2
    Register<bit<32>,_>(TABLE_SIZE) dns_cip_reg_2; 
    RegisterAction<bit<32>,_,bit<1>> (dns_cip_reg_2) dns_cip_reg_2_check_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            if (value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_cip_reg_2) dns_cip_reg_2_check_bidir_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            //if ( (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) || (value.sip == headers.ipv4.dst && value.cip == headers.dns_ip.rdata) ) {

            if (value == headers.ipv4.src || value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_reg_2) dns_cip_reg_2_update_action = {
        void apply(inout bit<32> value) {
            value = headers.ipv4.dst;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE) dns_sip_reg_2; 
    RegisterAction<bit<32>,_,bit<1>> (dns_sip_reg_2) dns_sip_reg_2_check_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            if (value == headers.dns_ip.rdata) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_sip_reg_2) dns_sip_reg_2_check_bidir_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            //if ( (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) || (value.sip == headers.ipv4.dst && value.cip == headers.dns_ip.rdata) ) {

            if (value == headers.ipv4.src || value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_reg_2) dns_sip_reg_2_update_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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

    // Register 3
    Register<bit<32>,_>(TABLE_SIZE) dns_cip_reg_3; 
    RegisterAction<bit<32>,_,bit<1>> (dns_cip_reg_3) dns_cip_reg_3_check_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            if (value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_cip_reg_3) dns_cip_reg_3_check_bidir_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            //if ( (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) || (value.sip == headers.ipv4.dst && value.cip == headers.dns_ip.rdata) ) {

            if (value == headers.ipv4.src || value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_reg_3) dns_cip_reg_3_update_action = {
        void apply(inout bit<32> value) {
            value = headers.ipv4.dst;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE) dns_sip_reg_3; 
    RegisterAction<bit<32>,_,bit<1>> (dns_sip_reg_3) dns_sip_reg_3_check_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            if (value == headers.dns_ip.rdata) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,bit<1>> (dns_sip_reg_3) dns_sip_reg_3_check_bidir_action = {
        void apply(inout bit<32> value, out bit<1> is_match) {
            //if ( (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) || (value.sip == headers.ipv4.dst && value.cip == headers.dns_ip.rdata) ) {

            if (value == headers.ipv4.src || value == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_reg_3) dns_sip_reg_3_update_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
            value = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_1) dns_cip_table_1_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
            value = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_1) dns_sip_table_1_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
            value = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_2) dns_cip_table_2_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
            value = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_2) dns_sip_table_2_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
 
    /*Register<bit<32>,_>(TABLE_SIZE,0) dns_cip_table_3;
    RegisterAction<bit<32>,_,bit<32>> (dns_cip_table_3) dns_cip_table_3_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_3) dns_cip_table_3_reg_write_ipv4dst_action = {
        void apply(inout bit<32> value) {
            value = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_cip_table_3) dns_cip_table_3_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
            value = headers.ipv4.dst;
        }
    };
    RegisterAction<bit<32>,_,void> (dns_sip_table_3) dns_sip_table_3_reg_write_dnsiprdata_action = {
        void apply(inout bit<32> value) {
            value = headers.dns_ip.rdata;
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
    };*/
 
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
    /*RegisterAction<bit<32>,_,bit<32>> (byte_counts_table) byte_counts_table_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };*/
    RegisterAction<bit<32>,_,void> (byte_counts_table) byte_counts_table_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + (bit<32>)headers.ipv4.len;
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

    // Define Hash
    Hash<bit<14>>(HashAlgorithm_t.CRC16) hash_1_dns;
    Hash<bit<14>>(HashAlgorithm_t.CRC16) hash_2_dns;
    Hash<bit<14>>(HashAlgorithm_t.CRC16) hash_3_dns;

    Hash<bit<14>>(HashAlgorithm_t.CRC16) hash_1;
    Hash<bit<14>>(HashAlgorithm_t.CRC16) hash_2;
    Hash<bit<14>>(HashAlgorithm_t.CRC16) hash_3;

    action match_domain(known_domain_id id) {
        ig_md.domain_id = id;
        ig_md.matched_domain = 1;
    }

    table known_domain_list {
        key = {
            headers.q1_part1.part: ternary;
            headers.q1_part2.part: ternary;
            headers.q1_part4.part: ternary;
            headers.q1_part8_1.part: ternary;
            headers.q1_part8_2.part: ternary;

            headers.q2_part1.part: ternary;
            headers.q2_part2.part: ternary;
            headers.q2_part4.part: ternary;
            headers.q2_part8_1.part: ternary;
            headers.q2_part8_2.part: ternary;

            headers.q3_part1.part: ternary;
            headers.q3_part2.part: ternary;
            headers.q3_part4.part: ternary;
            headers.q3_part8_1.part: ternary;
            headers.q3_part8_2.part: ternary;

            headers.q4_part1.part: ternary;
            headers.q4_part2.part: ternary;
            headers.q4_part4.part: ternary;
            headers.q4_part8_1.part: ternary;
            headers.q4_part8_2.part: ternary;
        }

        actions = {
            match_domain;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    action match_banned_dns_dst() {
        ig_md.matched_domain = 0;
    }

    // Incorporate both banned and allowable dns in this single table
    table banned_dns_dst {
        key = {
            headers.ipv4.dst: lpm;
        }

        actions = {
            match_banned_dns_dst;
            NoAction;
        }
        size = NUM_BANNED_DST_IP;
        default_action = NoAction();
    }

    apply {
        if(ig_md.parsed_answer == 1) {
            ig_md.domain_id = 0;
            ig_md.matched_domain = 0;

            known_domain_list.apply();
            //allowable_dns_dst.apply();
            banned_dns_dst.apply();

            if (ig_md.matched_domain == 1) {

                // Increment total DNS queries for this domain name
                dns_total_queried_reg_inc_action.execute(ig_md.domain_id);
                
                ig_md.index_1_dns = (bit<32>) hash_1_dns.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w134140211);
                ig_md.index_2_dns = (bit<32>) hash_2_dns.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w187182238);
                //ig_md.index_3_dns = (bit<32>) hash_3_dns.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w232108253);

                ig_md.already_matched = 0;
                bool is_resubmitted=(bool) ig_intr_md.resubmit_flag;

                if (!is_resubmitted) {
                    // access table 1
                    // Read sip_cip table
                    bit<1> is_match_cip =  dns_cip_reg_1_check_action.execute(ig_md.index_1_dns);
                    bit<1> is_match_sip = dns_sip_reg_1_check_action.execute(ig_md.index_1_dns);
                    
                    // If sip and cip matches, just update timestamp
                    if (is_match_cip == 1 && is_match_sip == 1) {
                        domain_tstamp_reg_1_update_tstamp_action.execute(ig_md.index_1_dns);
                        ig_md.already_matched = 1;
                    }
                    else { 
                        // Check timestamp
                        bit<1> timed_out = domain_tstamp_reg_1_check_tstamp_action.execute(ig_md.index_1_dns);

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
                    dns_cip_reg_1_update_action.execute(ig_md.index_1_dns);
                    dns_sip_reg_1_update_action.execute(ig_md.index_1_dns);
                    domain_tstamp_reg_1_update_tstamp_domain_action.execute(ig_md.index_1_dns);
                    ig_md.already_matched = 1;
                }
                

                // access table 2
                if (ig_md.already_matched == 0) {

                    if (!is_resubmitted) {
                        // Read sip_cip table
                        bit<1> is_match_cip =  dns_cip_reg_2_check_action.execute(ig_md.index_2_dns);
                        bit<1> is_match_sip = dns_sip_reg_2_check_action.execute(ig_md.index_2_dns);
                        
                        // If sip and cip matches, just update timestamp
                        if (is_match_cip == 1 && is_match_sip == 1) {
                            domain_tstamp_reg_2_update_tstamp_action.execute(ig_md.index_2_dns);
                            ig_md.already_matched = 1;
                        }
                        else { 
                            // Check timestamp
                            bit<1> timed_out = domain_tstamp_reg_2_check_tstamp_action.execute(ig_md.index_2_dns);

                            // If entry timed out, replace entry. For this, resubmit packet.
                            if (timed_out == 1) {
                                // Set resubmit
                                ig_intr_dprsr_md.resubmit_type = 1;
                            }

                            // Else, we have a collision that we cannot replace reg_2.
                            // Continue to reg_3.
                        }
                    }
                    else {
                        dns_cip_reg_2_update_action.execute(ig_md.index_2_dns);
                        dns_sip_reg_2_update_action.execute(ig_md.index_2_dns);
                        domain_tstamp_reg_2_update_tstamp_domain_action.execute(ig_md.index_2_dns);
                        ig_md.already_matched = 1;
                    }
                    
                }

                // access table 3
                /*if (ig_md.already_matched == 0) {

                    if (!is_resubmitted) {
                        bit<1> is_match_cip =  dns_cip_reg_3_check_action.execute(ig_md.index_3_dns);
                        bit<1> is_match_sip = dns_sip_reg_3_check_action.execute(ig_md.index_3_dns);
                            
                        // If sip and cip matches, just update timestamp
                        if (is_match_cip == 1 && is_match_sip == 1) {
                            domain_tstamp_reg_3_update_tstamp_action.execute(ig_md.index_3_dns);
                            ig_md.already_matched = 1;
                        }
                        else { 
                            // Check timestamp
                            bit<1> timed_out = domain_tstamp_reg_3_check_tstamp_action.execute(ig_md.index_3_dns);

                            // If entry timed out, replace entry. For this, resubmit packet.
                            if (timed_out == 1) {
                                // Set resubmit
                                ig_intr_dprsr_md.resubmit_type = 1;
                            }

                            // Else, we have a collision that we cannot replace reg_3.
                        }
                    }
                    else {
                        dns_cip_reg_3_update_action.execute(ig_md.index_3_dns);
                        dns_sip_reg_3_update_action.execute(ig_md.index_3_dns);
                        domain_tstamp_reg_3_update_tstamp_domain_action.execute(ig_md.index_3_dns);
                        ig_md.already_matched = 1;
                    }
                    
                }*/

                if (ig_md.already_matched == 0) {
                    // Increment total DNS queries missed for this domain name

                    dns_total_missed_reg_inc_action.execute(ig_md.domain_id);
                }
            }
        }
        // HANDLE NORMAL, NON-DNS PACKETS
        else if (ig_md.is_ip == 1 && ig_md.is_dns == 0) {
            //hash(ig_md.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.src, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
            //hash(ig_md.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.src, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
            //hash(ig_md.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.src, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
            
            ig_md.index_1 = (bit<32>) hash_1.get(headers.ipv4.src + headers.ipv4.dst + 32w134140211);
            ig_md.index_2 = (bit<32>) hash_2.get(headers.ipv4.src + headers.ipv4.dst + 32w187182238);
            //ig_md.index_3 = (bit<32>) hash_3.get(headers.ipv4.src + headers.ipv4.dst + 32w232108253);

            bit<1> sip_matched = 0;
            bit<1> cip_matched = 0;
            bit<32> index_for_update = 0;
            ig_md.already_matched = 0;

            // register_1
            cip_matched = dns_cip_reg_1_check_bidir_action.execute(ig_md.index_1);
            sip_matched = dns_sip_reg_1_check_bidir_action.execute(ig_md.index_1);
            
            if (cip_matched == 1 && sip_matched == 1) {
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
                cip_matched = dns_cip_reg_2_check_bidir_action.execute(ig_md.index_2);
                sip_matched = dns_sip_reg_2_check_bidir_action.execute(ig_md.index_2);
                
                if (cip_matched == 1 && sip_matched == 1) {
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
            /*if (ig_md.already_matched == 0) {
                cip_matched = dns_cip_reg_3_check_bidir_action.execute(ig_md.index_3);
                sip_matched = dns_sip_reg_3_check_bidir_action.execute(ig_md.index_3);
                if (cip_matched == 1 && sip_matched == 1) {
                    // Get domain_id and udpate timestamp
                    ig_md.domain_id = domain_tstamp_reg_3_get_domain_and_update_ts_action.execute(ig_md.index_3);

                    // Update packet_count, update byte_count
                    //packet_counts_table_reg_inc_action.execute(ig_md.index_3);
                    //byte_counts_table_reg_inc_action.execute(ig_md.index_3);
                    index_for_update = ig_md.index_3;
                    ig_md.already_matched = 1;
                }
            }*/

            if (ig_md.already_matched == 1) {
                packet_counts_table_reg_inc_action.execute(index_for_update);
                byte_counts_table_reg_inc_action.execute(index_for_update);
            }
        }
	}
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout Parsed_packet hdr,
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
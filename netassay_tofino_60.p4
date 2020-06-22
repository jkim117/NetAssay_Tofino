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
    bit<16> rd_length;
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
struct user_metadata_t {
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
	bit<1> is_ip;
    bit<3>  unused;

    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
    bit<1> matched_domain;
    bit<32> domain_id;
    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;
    bit<32> index_4;
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

struct eg_metadata_t {
}

// parsers
parser TopIngressParser(packet_in pkt,
           out Parsed_packet p,
           out user_metadata_t user_metadata,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    ParserCounter() counter;

    state start {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
        user_metadata.do_dns = 0;
        user_metadata.recur_desired = 0;
        user_metadata.response_set = 0;
		user_metadata.is_dns = 0;
		user_metadata.is_ip = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		user_metadata.is_ip = 1;
        user_metadata.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}

	state parse_udp {
        pkt.extract(p.udp);

		transition select(p.udp.dport == 53 || p.udp.sport == 53) {
			true: parse_dns_header;
			false: accept;
		}
	}

	state parse_dns_header {
        pkt.extract(p.dns_header);
		user_metadata.is_dns = 1;

        user_metadata.last_label = 0;

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
        user_metadata.last_label = 1;

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
        user_metadata.last_label = 2;

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
        user_metadata.last_label = 3;

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
        user_metadata.last_label = 4;

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
        user_metadata.last_label = 5;

        transition select(p.label5.label) {
            0: parse_query_tc;
            default: accept;
        }
    }

    state parse_query_tc {
        pkt.extract(p.query_tc);
        user_metadata.parsed_answer = 0;
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
        counter.set((p.dns_answer.rd_length);

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
        user_metadata.parsed_answer = 1;

        transition accept;
    }
}
/**************************END OF PARSER**************************/

control TopVerifyChecksum(inout Parsed_packet headers, inout user_metadata_t user_metadata) {   
    apply {  }
}

control TopIngress(inout Parsed_packet headers,
                inout user_metadata_t user_metadata,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // PRECISION STYLE TABLES
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

    Register<bit<32>,_>(TABLE_SIZE,0) dns_sip_table_1;
    RegisterAction<bit<32>,_,bit<32>> (dns_sip_table_1) dns_sip_table_1_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
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
            value = user_metadata.domain_id;
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
 
    Register<bit<32>,_>(TABLE_SIZE,0) dns_sip_table_2;
    RegisterAction<bit<32>,_,bit<32>> (dns_sip_table_2) dns_sip_table_2_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
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
            value = user_metadata.domain_id;
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
            value = headers.ipv4.dst;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE,0) dns_sip_table_3;
    RegisterAction<bit<32>,_,bit<32>> (dns_sip_table_3) dns_sip_table_3_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
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
            value = user_metadata.domain_id;
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
    Register<bit<64>,_>(NUM_KNOWN_DOMAINS) packet_counts_table;
    RegisterAction<bit<64>,_,void> (packet_counts_table) packet_counts_table_reg_inc_action = {
        void apply(inout bit<64> value) {
            value = value + 1;
        }
    };

    Register<bit<64>,_>(NUM_KNOWN_DOMAINS) byte_counts_table;
    RegisterAction<bit<64>,_,void> (byte_counts_table) byte_counts_table_reg_inc_action = {
        void apply(inout bit<64> value) {
            value = value + (bit<64>)headers.ipv4.len;
        }
    };

    // REGISTER ARRAY FOR KEEPING TRACK OF OVERFLOW DNS RESPONSES
    Register<bit<64>,_>(NUM_KNOWN_DOMAINS) dns_total_queried;
    RegisterAction<bit<64>,_, void> (dns_total_queried) dns_total_queried_reg_inc_action = {
        void apply(inout bit<64> value) {
            value = value + 1;
        }
    };
 
    Register<bit<64>,_>(NUM_KNOWN_DOMAINS) dns_total_missed;
    RegisterAction<bit<64>,_, void> (dns_total_missed) dns_total_missed_reg_inc_action = {
        void apply(inout bit<64> value) {
            value = value + 1;
        }
    };

    // Define Hash
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;

    action match_domain(known_domain_id id) {
        user_metadata.domain_id = id;
        user_metadata.matched_domain = 1;
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
        user_metadata.matched_domain = 0;
    }

    table allowable_dns_dst {
        key = {
            headers.ipv4.dst: lpm;
        }

        actions = {
            match_banned_dns_dst;
            NoAction;
        }
        size = NUM_ALLOWABLE_DST_IP;
        default_action = match_banned_dns_dst();
    }

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
        if(user_metadata.parsed_answer == 1) {
            user_metadata.domain_id = 0;
            user_metadata.matched_domain = 0;

            known_domain_list.apply();
            allowable_dns_dst.apply();
            banned_dns_dst.apply();

            if (user_metadata.matched_domain == 1) {

                // Increment total DNS queries for this domain name
                dns_total_queried_reg_inc_action.execute(user_metadata.domain_id);
                
                user_metadata.index_1 = (bit<32>) hash_1.get({headers.dns_ip.rdata, 7w11, headers.ipv4.dst});
                user_metadata.index_2 = (bit<32>) hash_1.get({3w5, headers.dns_ip.rdata, 5w3, headers.ipv4.dst});
                user_metadata.index_3 = (bit<32>) hash_1.get({2w0, headers.dns_ip.rdata, 1w1, headers.ipv4.dst});

                user_metadata.already_matched = 0;

                // access table 1
                user_metadata.temp_cip = dns_cip_table_1_reg_read_action.execute(user_metadata.index_1);
                user_metadata.temp_sip = dns_sip_table_1_reg_read_action.execute(user_metadata.index_1);
                user_metadata.temp_timestamp = (bit<48>) dns_timestamp_table_1_reg_read_action.execute(user_metadata.index_1); 

                if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < ig_intr_prsr_md.global_tstamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {

                    dns_cip_table_1_reg_write_ipv4dst_action.execute(user_metadata.index_1);
                    dns_sip_table_1_reg_write_dnsiprdata_action.execute(user_metadata.index_1);
                    dns_timestamp_table_1_reg_write_tstamp_action.execute(user_metadata.index_1);
                    dns_name_table_1_reg_write_domainid_action.execute(user_metadata.index_1);

                    user_metadata.already_matched = 1;
                }

                // access table 2
                if (user_metadata.already_matched == 0) {
                    
                    user_metadata.temp_cip = dns_cip_table_2_reg_read_action.execute(user_metadata.index_2);
                    user_metadata.temp_sip = dns_sip_table_2_reg_read_action.execute(user_metadata.index_2);
                    user_metadata.temp_timestamp = (bit<48>) dns_timestamp_table_2_reg_read_action.execute(user_metadata.index_2);

                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < ig_intr_prsr_md.global_tstamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {

                        dns_cip_table_2_reg_write_ipv4dst_action.execute(user_metadata.index_2);
                        dns_sip_table_2_reg_write_dnsiprdata_action.execute(user_metadata.index_2);
                        dns_timestamp_table_2_reg_write_tstamp_action.execute(user_metadata.index_2);
                        dns_name_table_2_reg_write_domainid_action.execute(user_metadata.index_2);

                        user_metadata.already_matched = 1;
                    }
                }

                // access table 3
                if (user_metadata.already_matched == 0) {

                    user_metadata.temp_cip = dns_cip_table_3_reg_read_action.execute(user_metadata.index_3);
                    user_metadata.temp_sip = dns_sip_table_3_reg_read_action.execute(user_metadata.index_3);
                    user_metadata.temp_timestamp = (bit<48>) dns_timestamp_table_3_reg_read_action.execute(user_metadata.index_3);

                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < ig_intr_prsr_md.global_tstamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {

                        dns_cip_table_3_reg_write_ipv4dst_action.execute(user_metadata.index_3);
                        dns_sip_table_3_reg_write_dnsiprdata_action.execute(user_metadata.index_3);
                        dns_timestamp_table_3_reg_write_tstamp_action.execute(user_metadata.index_3);
                        dns_name_table_3_reg_write_domainid_action.execute(user_metadata.index_3);

                        user_metadata.already_matched = 1;
                    }
                }

                if (user_metadata.already_matched == 0) {
                    // Increment total DNS queries missed for this domain name

                    dns_total_missed_reg_inc_action.execute(user_metadata.domain_id);
                }
            }
        }
        // HANDLE NORMAL, NON-DNS PACKETS
        else if (user_metadata.is_ip == 1 && user_metadata.is_dns == 0) {
            //hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.src, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
            //hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.src, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
            //hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.src, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
            
            user_metadata.index_1 = (bit<32>) hash_1.get({headers.ipv4.src, 7w11, headers.ipv4.dst});
            user_metadata.index_2 = (bit<32>) hash_1.get({3w5, headers.ipv4.src, 5w3, headers.ipv4.dst});
            user_metadata.index_3 = (bit<32>) hash_1.get({2w0, headers.ipv4.src, 1w1, headers.ipv4.dst});

            //dns_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
            //dns_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
            
            user_metadata.temp_cip = dns_cip_table_1_reg_read_action.execute(user_metadata.index_1);
            user_metadata.temp_sip = dns_sip_table_1_reg_read_action.execute(user_metadata.index_1);

            if (headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) {
                //dns_name_table_1.read(user_metadata.domain_id, user_metadata.index_1);
                //packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                //packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                //byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                //byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<64>)headers.ipv4.len);
                //dns_timestamp_table_1.write(user_metadata.index_1, (bit<32>) ig_intr_prsr_md.global_tstamp);

                user_metadata.domain_id = dns_name_table_1_reg_read_action.execute(user_metadata.index_1);
                packet_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                byte_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                dns_timestamp_table_1_reg_write_tstamp_action.execute(user_metadata.index_1);
           }

            //dns_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
            //dns_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);

            user_metadata.temp_cip = dns_cip_table_2_reg_read_action.execute(user_metadata.index_2);
            user_metadata.temp_sip = dns_sip_table_2_reg_read_action.execute(user_metadata.index_2);
            if (headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) {
                //dns_name_table_2.read(user_metadata.domain_id, user_metadata.index_2);
                //packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                //packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                //byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                //byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<64>)headers.ipv4.len);
                //dns_timestamp_table_2.write(user_metadata.index_2, (bit<32>) ig_intr_prsr_md.global_tstamp);

                user_metadata.domain_id = dns_name_table_2_reg_read_action.execute(user_metadata.index_2);
                packet_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                byte_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                dns_timestamp_table_2_reg_write_tstamp_action.execute(user_metadata.index_2);
            }

            //dns_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
            //dns_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
            user_metadata.temp_cip = dns_cip_table_3_reg_read_action.execute(user_metadata.index_3);
            user_metadata.temp_sip = dns_sip_table_3_reg_read_action.execute(user_metadata.index_3);
            if (headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) {
                //dns_name_table_3.read(user_metadata.domain_id, user_metadata.index_3);
                //packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                //packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                //byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                //byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<64>)headers.ipv4.len);
                //dns_timestamp_table_3.write(user_metadata.index_3, (bit<32>) ig_intr_prsr_md.global_tstamp);
            
                user_metadata.domain_id = dns_name_table_3_reg_read_action.execute(user_metadata.index_3);
                packet_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                byte_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                dns_timestamp_table_3_reg_write_tstamp_action.execute(user_metadata.index_3);
            }

            //hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.dst, 7w11, headers.ipv4.src}, HASH_TABLE_MAX);
            //hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.dst, 5w3, headers.ipv4.src}, HASH_TABLE_MAX);
            //hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.dst, 1w1, headers.ipv4.src}, HASH_TABLE_MAX);

            user_metadata.index_1 = (bit<32>) hash_1.get({headers.ipv4.dst, 7w11, headers.ipv4.src});
            user_metadata.index_2 = (bit<32>) hash_1.get({3w5, headers.ipv4.dst, 5w3, headers.ipv4.src});
            user_metadata.index_3 = (bit<32>) hash_1.get({2w0, headers.ipv4.dst, 1w1, headers.ipv4.src});

            //dns_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
            //dns_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
            user_metadata.temp_cip = dns_cip_table_1_reg_read_action.execute(user_metadata.index_1);
            user_metadata.temp_sip = dns_sip_table_1_reg_read_action.execute(user_metadata.index_1);
 
            if (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip) {
                //dns_name_table_1.read(user_metadata.domain_id, user_metadata.index_1);
                //packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                //packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                //byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                //byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<64>)headers.ipv4.len);
                //dns_timestamp_table_1.write(user_metadata.index_1, (bit<32>) ig_intr_prsr_md.global_tstamp);

                user_metadata.domain_id = dns_name_table_1_reg_read_action.execute(user_metadata.index_1);
                packet_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                byte_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                dns_timestamp_table_1_reg_write_tstamp_action.execute(user_metadata.index_1);
            }

            //dns_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
            //dns_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
            user_metadata.temp_cip = dns_cip_table_2_reg_read_action.execute(user_metadata.index_2);
            user_metadata.temp_sip = dns_sip_table_2_reg_read_action.execute(user_metadata.index_2);
 
            if (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip) {
                //dns_name_table_2.read(user_metadata.domain_id, user_metadata.index_2);
                //packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                //packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                //byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                //byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<64>)headers.ipv4.len);
                //dns_timestamp_table_2.write(user_metadata.index_2, (bit<32>) ig_intr_prsr_md.global_tstamp);
            
                user_metadata.domain_id = dns_name_table_2_reg_read_action.execute(user_metadata.index_2);
                packet_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                byte_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                dns_timestamp_table_2_reg_write_tstamp_action.execute(user_metadata.index_2);
            }

            //dns_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
            //dns_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
            user_metadata.temp_cip = dns_cip_table_3_reg_read_action.execute(user_metadata.index_3);
            user_metadata.temp_sip = dns_sip_table_3_reg_read_action.execute(user_metadata.index_3);
 
            if (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip) {
                //dns_name_table_3.read(user_metadata.domain_id, user_metadata.index_3);
                //packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                //packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                //byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                //byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<64>)headers.ipv4.len);
                //dns_timestamp_table_3.write(user_metadata.index_3, (bit<32>) ig_intr_prsr_md.global_tstamp);
 
                user_metadata.domain_id = dns_name_table_3_reg_read_action.execute(user_metadata.index_3);
                packet_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                byte_counts_table_reg_inc_action.execute(user_metadata.domain_id);
                dns_timestamp_table_3_reg_write_tstamp_action.execute(user_metadata.index_3);
           }
        }
	}
}

control TopIngressDeparser(packet_out pkt,
                          inout Parsed_packet hdr,
                          in user_metadata_t user_metadata,
                          in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_csum;

    apply {
        if(hdr.ipv4.isValid()) {
            hdr.ipv4.chksum = ipv4_csum.update({
                   hdr.ipv4.version,
                   hdr.ipv4.ihl,
                   hdr.ipv4.tos,
                   hdr.ipv4.len,
                   hdr.ipv4.id,
                   hdr.ipv4.flags,
                   hdr.ipv4.frag,
                   hdr.ipv4.ttl,
                   hdr.ipv4.proto,
                   hdr.ipv4.src,
                   hdr.ipv4.dst});
        }
    }
}

parser TopEgressParser(packet_in packet,
                       out Parsed_packet hdr,
                       out eg_metadata_t eg_md,
                       out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        transition accept;
    }
}

control TopEgress(inout Parsed_packet headers,
                 inout eg_metadata_t eg_md,
                 in egress_intrinsic_metadata_t eg_intr_md,
                 in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
                 inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
                 inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {  }
}

//control TopComputeChecksum(inout Parsed_packet headers, inout user_metadata_t user_metadata) {
//    apply {
//	update_checksum(
//	    headers.ipv4.isValid(),
//            {
//                headers.ipv4.version,
//                headers.ipv4.ihl,
//                headers.ipv4.tos,
//                headers.ipv4.len,
//                headers.ipv4.id,
//                headers.ipv4.flags,
//                headers.ipv4.frag,
//                headers.ipv4.ttl,
//                headers.ipv4.proto,
//                headers.ipv4.src,
//                headers.ipv4.dst
//            },
//            headers.ipv4.chksum,
//            HashAlgorithm.csum16);
//    }
//}

// Deparser Implementation
control TopDeparser(packet_out b,
                    in Parsed_packet p) { 
    apply {
    }
}

control TopEgressDeparser(packet_out packet, 
                         inout Parsed_packet hdr, 
                         in eg_metadata_t eg_md,
                         in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    apply {  }
}

// Instantiate the switch
//V1Switch(TopParser(), TopVerifyChecksum(), TopIngress(), TopEgress(), TopComputeChecksum(), TopDeparser()) main;

Pipeline(TopIngressParser(),
         TopIngress(),
         TopIngressDeparser(),
         TopEgressParser(),
         TopEgress(),
         TopEgressDeparser()
         ) pipe;

Switch(pipe) main;

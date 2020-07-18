#include <core.p4>
#include <tna.p4>

#define IP_BINS 2
#define NUM_KNOWN_IPS 1000

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;

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

// List of all recognized headers
struct Parsed_packet { 
    ethernet_h ethernet;
    ipv4_h ipv4;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct ig_metadata_t {
	bit<1> is_ip;
    bit<1> matched_ip;
}

struct eg_metadata_t {
}

// parsers

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

parser SwitchIngressParser(packet_in pkt,
           out Parsed_packet p,
           out ig_metadata_t ig_md,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
		ig_md.is_ip = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		ig_md.is_ip = 1;
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
             
    apply {        
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
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
 
    // REGISTER ARRAY FOR COLLECTING COUNTS ON TRAFFIC WITH KNOWN IP ADDRESSES
    Register<bit<32>,_>(IP_BINS) packet_counts_table;
    RegisterAction<bit<32>,_,void> (packet_counts_table) packet_counts_table_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };


    action match_ip() {
        ig_md.matched_ip = 1;
    }

    table known_ip_list {
        key = {
            headers.ipv4.src: exact;
        }

        actions = {
            match_ip;
            NoAction;
        }
        size = NUM_KNOWN_IPS;
        default_action = NoAction();
    }

    apply {
        if (ig_md.is_ip == 1) {
            ig_md.matched_ip = 0;

            known_ip_list.apply();

            if (ig_md.matched_ip == 1) {
                packet_counts_table_reg_inc_action.execute(1);
            }
            else {
                packet_counts_table_reg_inc_action.execute(0);
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
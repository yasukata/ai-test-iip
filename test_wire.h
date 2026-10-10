/* Wire layouts used only by the test packet builders and assertions. */
#ifndef TEST_WIRE_H
#define TEST_WIRE_H
struct iip_ip4_hdr {
	uint8_t vl, tos;
	uint16_t len_be, id_be, off_be;
	uint8_t ttl, proto;
	uint16_t csum_be;
	uint32_t src_be, dst_be;
};
struct iip_tcp_hdr {
	uint16_t src_be, dst_be;
	uint32_t seq_be, ack_seq_be;
	uint16_t flags, win_be, csum_be, urg_p_be;
};
struct iip_udp_hdr { uint16_t src_be, dst_be, len_be, csum_be; };
struct iip_icmp_hdr { uint8_t type, code; uint16_t csum_be; uint8_t rest[4]; };
struct iip_arp_hdr { uint16_t hw_be, proto_be; uint8_t lhw, lproto; uint16_t op_be; };
struct iip_l4_ip4_pseudo_hdr {
	uint32_t ip4_src_be, ip4_dst_be;
	uint8_t pad, proto;
	uint16_t len_be;
};
_Static_assert(sizeof(struct iip_ip4_hdr) == 20, "IPv4 wire header");
_Static_assert(sizeof(struct iip_tcp_hdr) == 20, "TCP wire header");
_Static_assert(sizeof(struct iip_l4_ip4_pseudo_hdr) == 12, "IPv4 pseudo header");
#endif

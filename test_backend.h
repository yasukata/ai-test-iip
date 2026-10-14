enum test_backend_callback_type {
	TEST_BACKEND_CONNECTED,
	TEST_BACKEND_ACCEPTED,
	TEST_BACKEND_PAYLOAD,
	TEST_BACKEND_CLOSE_WAIT,
	TEST_BACKEND_CLOSED,
	TEST_BACKEND_FASTOPEN_REQUEST,
	TEST_BACKEND_URGENT,
};

static uint16_t iip_ops_l2_hdr_len(void *, void *);
/* Binding between the current macro API and the test packet/event backend. */
static void *iip_ops_pkt_alloc(void *);
static void iip_ops_pkt_free(void *, void *);
static void *iip_ops_pkt_get_data(void *, void *);
static uint16_t iip_ops_pkt_get_len(void *, void *);
static void iip_ops_pkt_set_len(void *, uint16_t, void *);
static void *iip_ops_pkt_clone(void *, void *);
static void iip_ops_pkt_scatter_gather_chain_append(void *, void *, void *);
static uint16_t test_pkt_get_capacity(void *, void *);
static void iip_ops_l2_push(void *, void *);
static int test_backend_ethernet_header(uint8_t *, uint8_t *, uint16_t, void *);
static bool test_backend_ethernet_match(uint8_t *, void *);
static bool test_backend_ipv4_match(uint8_t *, void *);
static bool test_backend_accept(struct iip_workspace *, uint32_t, void *);
static bool test_backend_ipv4_tcp_input_filter(struct iip_workspace *, uint32_t, void *);
static int test_backend_callback(struct iip_workspace *, uint32_t, uint32_t, enum test_backend_callback_type, void *);
static int test_backend_udp(struct iip_workspace *, uint32_t, void *);
static int test_backend_arp(struct iip_workspace *, void *, void *);
static void test_event_ip4_negative_advice(void *, void *);
static void test_event_tcp_icmp_error(void *, void *, uint8_t, uint8_t);
static void *test_current_opaque;
#define IIP_OPS_PKT_VALID() do { iip_ret_bool = pkt != NULL; } while (0)
#define IIP_OPS_PKT_ALLOC() do { *pkt = iip_ops_pkt_alloc(opaque); iip_ret_int = *pkt ? 0 : -1; } while (0)
#define IIP_OPS_PKT_FREE() do { iip_ops_pkt_free(pkt, opaque); iip_ret_int = 0; } while (0)
#define IIP_OPS_PKT_GET_DATA() do { iip_ret_u8_ptr = iip_ops_pkt_get_data(pkt, opaque); } while (0)
#define IIP_OPS_PKT_GET_LEN() do { iip_ret_len = iip_ops_pkt_get_len(pkt, opaque); } while (0)
#define IIP_OPS_PKT_SET_LEN() do { iip_ops_pkt_set_len(pkt, len, opaque); iip_ret_int = 0; } while (0)
#define IIP_OPS_PKT_GET_CAPACITY() do { iip_ret_len = test_pkt_get_capacity(pkt, opaque); } while (0)
#define IIP_OPS_PKT_CLONE() do { *cloned_pkt = iip_ops_pkt_clone(pkt, opaque); iip_ret_int = *cloned_pkt ? 0 : -1; } while (0)
#define IIP_OPS_PKT_SCATTER_GATHER_APPEND() do { iip_ops_pkt_scatter_gather_chain_append(head_pkt, tail_pkt, opaque); iip_ret_int = 0; } while (0)
#define IIP_OPS_ETHERNET_HDR_CRAFT() do { iip_ret_int = test_backend_ethernet_header(buf, dst_addr, proto_be, opaque); } while (0)
#define IIP_OPS_ETHERNET_ADDR_MATCH() do { iip_ret_bool = test_backend_ethernet_match(buf, opaque); } while (0)
#define IIP_OPS_IPV4_ADDR_MATCH() do { iip_ret_bool = test_backend_ipv4_match((uint8_t *)iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN + II_ARP_HDR_LEN + 16, opaque); } while (0)
#define IIP_OPS_ETHERNET_PUSH() do { iip_ops_l2_push(pkt, opaque); iip_ret_int = 0; } while (0)
#define IIP_OPS_TCP_ACCEPT() do { iip_ret_bool = test_backend_accept(w, pb_id, opaque); } while (0)
#undef IIP_OPS_IPV4_TCP_INPUT_FILTER
#define IIP_OPS_IPV4_TCP_INPUT_FILTER() do { iip_ret_bool = test_backend_ipv4_tcp_input_filter(w, pb_id, opaque); } while (0)
#define IIP_OPS_TCP_CONNECTED() do { iip_ret_int = test_backend_callback(w, conn_id, pb_id, TEST_BACKEND_CONNECTED, opaque); } while (0)
#define IIP_OPS_TCP_ACCEPTED() do { iip_ret_int = test_backend_callback(w, conn_id, pb_id, TEST_BACKEND_ACCEPTED, opaque); } while (0)
#define IIP_OPS_TCP_PAYLOAD() do { iip_ret_int = test_backend_callback(w, conn_id, pb_id, TEST_BACKEND_PAYLOAD, opaque); } while (0)
#define IIP_OPS_TCP_STATE_CLOSE_WAIT() do { iip_ret_int = test_backend_callback(w, conn_id, pb_id, TEST_BACKEND_CLOSE_WAIT, opaque); } while (0)
#define IIP_OPS_TCP_CLOSED() do { iip_ret_int = test_backend_callback(w, conn_id, 0, TEST_BACKEND_CLOSED, opaque); } while (0)
#define IIP_OPS_ARP_ETHERNET_REPLY() do { iip_ret_int = test_backend_arp(w, rx_pkt, opaque); } while (0)
#define IIP_OPS_UDP_PAYLOAD() do { iip_ret_int = test_backend_udp(w, pb_id, opaque); } while (0)
#define IIP_OPS_TCP_IP_NEGATIVE_ADVICE() do { test_event_ip4_negative_advice(test_current_opaque, &II_TCP_CONN(conn_id)); iip_ret_int = 0; } while (0)
#define IIP_OPS_TCP_FASTOPEN_REQUEST() do { iip_ret_int = test_backend_callback(w, conn_id, pb_id, TEST_BACKEND_FASTOPEN_REQUEST, opaque); } while (0)
#define IIP_OPS_TCP_IPV4_FASTOPEN_CHECK() do { iip_ret_bool = test_backend_fastopen(w, conn_id, tcp_opt + l + 2, tcp_opt[l + 1] - 2); } while (0)
static bool test_backend_fastopen(struct iip_workspace *, uint32_t, const uint8_t *, uint8_t);

/* IIP_OPS_TCP_URGENT() is expanded in ii_tcp_rx_push(), where pb_id is the
 * packet just received and push_pb_id is the in-order segment currently
 * being processed (possibly taken from the out-of-order queue). Report the
 * segment that carried URG so the application sees its SEG.SEQ and SEG.UP. */
#define IIP_OPS_TCP_URGENT() do { iip_ret_int = test_backend_callback(w, conn_id, push_pb_id, TEST_BACKEND_URGENT, opaque); } while (0)

/* Apply the test backend's keyed tuple offset at connection initialization.
 * The core has already initialized the send sequence fields from ISS. */
#undef IIP_OPS_TCP_CONN_INIT
#define IIP_OPS_TCP_CONN_INIT() do { \
	II_TCP_CONN(conn_id).iss += iip_ops_tcp_iss_off( \
		src_ipv4_be, dst_ipv4_be, src_port_be, dst_port_be); \
	II_TCP_CONN(conn_id).sent_seq = \
		II_TCP_CONN(conn_id).seq = \
		II_TCP_CONN(conn_id).acked_seq = II_TCP_CONN(conn_id).iss; \
} while (0)

/* IIP_OPS_TCP_ICMP_RECEIVED_ERROR() is expanded where iip has matched the
 * datagram quoted in an ICMP error to a TCP connection.  buf points to the
 * ICMP message (type at buf[0], code at buf[1]) and conn_id identifies the
 * connection. */
#define IIP_OPS_TCP_ICMP_RECEIVED_ERROR() do { \
	test_event_tcp_icmp_error(opaque, &II_TCP_CONN(conn_id), buf[0], buf[1]); \
	iip_ret_int = 0; \
} while (0)

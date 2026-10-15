/* Shared result handling, process isolation, assertions, and connection fixtures.
 * Included by main.c after its shared packet/backend helpers.
 */

#include "test_process.h"

static int __attribute__((format(printf, 3, 4)))
test_condition_failed(const char *scenario, unsigned int line,
		const char *format, ...)
{
	va_list args, copy;

	assert(format);
	fprintf(stderr, "FAILED CONDITION [%s:%u]: ", scenario, line);
	va_start(args, format);
	va_copy(copy, args);
	vsnprintf(test_failure_detail, sizeof(test_failure_detail), format, copy);
	va_end(copy);
	vfprintf(stderr, format, args);
	va_end(args);
	fputc('\n', stderr);
	return 0;
}

#define TEST_CONDITION(_condition, ...) \
	do { \
		if (!(_condition)) \
			return test_condition_failed(__func__, __LINE__, __VA_ARGS__); \
	} while (0)

#define TEST_ACCUMULATE(_ok, _condition, ...) \
	do { \
		if (!(_condition)) { \
			(void)test_condition_failed(__func__, __LINE__, __VA_ARGS__); \
			(_ok) = 0; \
		} \
	} while (0)

/* Result-returning assertions keep the same detail in stderr and JSON/TAP. */
#define TEST_REQUIRE(_why, _condition, ...) \
    do { \
        if (!(_condition)) { \
            test_condition_failed(__func__, __LINE__, __VA_ARGS__); \
            *(_why) = test_failure_detail; \
            return RESULT_FAIL; \
        } \
    } while (0)

struct fixture {
	struct test_state state;
	struct iip_workspace *ws;
	struct ii_tcp_conn *conn;
	uint8_t local_mac[6];
	uint8_t peer_mac[6];
	uint8_t icmp_quote[28];
	uint8_t icmp_quote_valid;
};

/* The urgent boundary known to the application equals @expected. */
static int test_urgent_boundary_is(const struct fixture *f, uint32_t expected)
{
	return f->state.urgent.valid && f->state.urgent.conn == f->conn &&
		f->state.urgent.ptr == expected;
}

static int fixture_init(struct fixture *f)
{
	uint32_t conn_id;
	memset(f, 0, sizeof(*f));
	f->local_mac[0] = 0x02;
	f->peer_mac[0] = 0x04;
	f->ws = calloc(1, sizeof(*f->ws));
	if (!f->ws) return test_condition_failed(__func__, __LINE__, "workspace allocation failed");
	test_workspace_init(f->ws);
	if (ii_alloc_tcp_conn(&f->ws->tcp_conns, &conn_id) != IIP_ERR_OK)
		return test_condition_failed(__func__, __LINE__, "connection allocation failed");
	f->conn = &f->ws->tcp_conns.array[conn_id];
	f->state.use_fake_clock = 1;
	f->state.now_ns = 1000000000ULL;
	f->ws->now_ms = 1000;
	f->ws->timer.prev_fast = 1000;
	f->ws->timer.prev_slow = 1000;
	f->ws->timer.prev_very_slow = 1000;
	f->ws->tcp.iss = 0x12345678U;
	test_api_conn_init(f->ws, f->conn, f->local_mac,
		ii_htonl(0xc0000201U), ii_htons(10000), f->peer_mac,
		ii_htonl(0xc6336402U), ii_htons(20000), II_TCP_STATE_ESTABLISHED, &f->state);
	f->state.use_fake_clock = 1;
	f->state.now_ns = 1000000000ULL;
	f->ws->now_ms = 1000;
	/* A fabricated established connection is idle from the fixture epoch. */
	f->conn->keepalive_ts = f->ws->now_ms;
	f->conn->ack_seq = 0;
	/* Base fixture has not negotiated timestamp options. */
	f->conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
	return 1;
}

static void *fixture_packet(struct fixture *f, uint8_t syn, uint16_t flags,
		uint16_t payload_len)
{
	void *payload = NULL;
	struct ii_pb *p;

	if (payload_len) {
		payload = iip_ops_pkt_alloc(&f->state);
		if (!payload)
			return NULL;
		memset(iip_ops_pkt_get_data(payload, &f->state), 0x5a, payload_len);
		iip_ops_pkt_set_len(payload, payload_len, &f->state);
	}
	test_api_push(f->ws, f->conn, payload, syn, !syn, 0, 0, flags,
			NULL, 0, &f->state);
	p = test_ring_end(f->ws, &f->conn->tx_ring, 0);
	if (!p)
		return NULL;
	test_ring_remove(f->ws, &f->conn->tx_ring, p);
	{
		void *pkt = test_emit_queued(f->ws, f->conn, p, &f->state);
		test_free_pb(f->ws, p, &f->state);
		return pkt;
	}
}

static int checksum_valid(void *pkt)
{
	struct iip_l4_ip4_pseudo_hdr pseudo;
	uint8_t *b[2];
	uint16_t l[2];
	uint16_t supplied = ii_ntohs(PB_TCP(pkt)->csum_be);

	pseudo.ip4_src_be = PB_IP4(pkt)->src_be;
	pseudo.ip4_dst_be = PB_IP4(pkt)->dst_be;
	pseudo.pad = 0;
	pseudo.proto = 6;
	pseudo.len_be = ii_htons(PB_TCP_HDR_LEN(pkt) * 4 + PB_TCP_PAYLOAD_LEN(pkt));
	b[0] = (uint8_t *)&pseudo;
	b[1] = (uint8_t *)PB_TCP(pkt);
	l[0] = sizeof(pseudo);
	l[1] = PB_TCP_HDR_LEN(pkt) * 4 + PB_TCP_PAYLOAD_LEN(pkt);
	return supplied == test_netcsum16(b, l, 2, supplied);
}

static int ip4_checksum_valid(void *pkt)
{
	uint8_t *b[1] = { (uint8_t *)PB_IP4(pkt) };
	uint16_t l[1] = { (uint16_t)((PB_IP4(pkt)->vl & 0x0f) * 4) };
	uint16_t supplied = ii_ntohs(PB_IP4(pkt)->csum_be);
	return supplied == test_netcsum16(b, l, 1, supplied);
}

static int icmp_checksum_valid(void *pkt)
{
	uint16_t ip_header_len = (uint16_t)(PB_IP4(pkt)->vl & 0x0f) << 2;
	uint16_t ip_total_len = ii_ntohs(PB_IP4(pkt)->len_be);
	uint8_t *b[1] = { (uint8_t *)PB_ICMP(pkt) };
	uint16_t l[1];
	uint16_t supplied;

	if (ip_total_len < ip_header_len + sizeof(struct iip_icmp_hdr))
		return 0;
	l[0] = ip_total_len - ip_header_len;
	supplied = ii_ntohs(PB_ICMP(pkt)->csum_be);
	return supplied == test_netcsum16(b, l, 1, supplied);
}

static uint8_t *option_find(void *pkt, uint8_t wanted)
{
	uint8_t *opt = PB_TCP_OPT(pkt);
	uint16_t at = 0, n = PB_TCP_OPTLEN(pkt);
	while (at < n) {
		uint8_t kind = opt[at];
		if (kind == 0)
			return NULL;
		if (kind == 1) {
			at++;
			continue;
		}
		if (at + 2 > n || opt[at + 1] < 2 || at + opt[at + 1] > n)
			return NULL;
		if (kind == wanted)
			return &opt[at];
		at += opt[at + 1];
	}
	return NULL;
}

static void fixture_incoming_spec(struct fixture *f,
		struct tcp_packet_spec *spec, uint32_t seq,
		const uint8_t *payload, uint16_t payload_len)
{
	tcp_packet_spec_init(spec);
	memcpy(spec->src_mac, f->peer_mac, sizeof(spec->src_mac));
	memcpy(spec->dst_mac, f->local_mac, sizeof(spec->dst_mac));
	spec->src_ip_be = ii_htonl(f->conn->dst_ip[0]);
	spec->dst_ip_be = ii_htonl(f->conn->src_ip[0]);
	spec->src_port_be = ii_htons(f->conn->dst_port);
	spec->dst_port_be = ii_htons(f->conn->src_port);
	spec->seq = seq;
	spec->ack_seq = f->conn->seq;
	spec->tcp_flags = TEST_TCP_ACK;
	spec->payload = payload;
	spec->payload_len = payload_len;
}

static void fixture_deliver(struct fixture *f, void *pkt)
{
	void *input[1] = { pkt };
	deliver(f->ws, f->local_mac, ii_htonl(f->conn->src_ip[0]), input, 1, &f->state);
}

static void *fixture_ip4_fragment(struct fixture *f, void *datagram,
		uint16_t payload_offset, uint16_t payload_len, uint8_t more_fragments)
{
	void *fragment;
	uint8_t *dst;
	const uint8_t *src;
	uint16_t ip_header_len;
	uint16_t ip_payload_len;
	uint16_t fragment_len;
	void *opaque = &f->state;

	ip_header_len = (PB_IP4(datagram)->vl & 0x0f) * 4;
	ip_payload_len = ii_ntohs(PB_IP4(datagram)->len_be) - ip_header_len;
	assert((payload_offset & 7U) == 0);
	assert(payload_offset <= ip_payload_len);
	assert(payload_len <= ip_payload_len - payload_offset);
	assert(!more_fragments || (payload_len & 7U) == 0);

	fragment_len = 14 + ip_header_len + payload_len;
	fragment = iip_ops_pkt_alloc(opaque);
	assert(fragment);
	dst = iip_ops_pkt_get_data(fragment, opaque);
	src = iip_ops_pkt_get_data(datagram, opaque);
	memcpy(dst, src, 14 + ip_header_len);
	memcpy(dst + 14 + ip_header_len,
			src + 14 + ip_header_len + payload_offset, payload_len);
	iip_ops_pkt_set_len(fragment, fragment_len, opaque);
	PB_IP4(fragment)->id_be = ii_htons(0x1234);
	PB_IP4(fragment)->off_be = ii_htons(
			(more_fragments ? 0x2000U : 0U) | (payload_offset / 8));
	PB_IP4(fragment)->len_be = ii_htons(ip_header_len + payload_len);
	update_ip4_checksum(fragment);
	return fragment;
}

static uint8_t test_tcp_urgent_query(const struct test_state *state,
		void *handle, uint32_t *queued)
{
	struct ii_tcp_conn *conn = handle;
	uint32_t remaining;

	/* Urgent data still to be read = application RCV.UP - RCV.NXT. iip
	 * hands received payload to the application immediately, so RCV.NXT
	 * is also the application's read position. */
	*queued = 0;
	if (!state->urgent.valid || state->urgent.conn != conn)
		return 0;
	remaining = state->urgent.ptr - conn->seq_next_expected;
	if (!remaining || remaining >= 2147483648U)
		return 0;
	*queued = remaining;
	return 1;
}

static void *fixture_icmp_error_packet(struct fixture *f, uint8_t type,
		uint8_t code)
{
	void *opaque = &f->state;
	void *pkt = iip_ops_pkt_alloc(opaque);
	uint8_t *data;
	struct iip_ip4_hdr *ip4, *quoted_ip4;
	struct iip_icmp_hdr *icmp;
	struct iip_tcp_hdr *quoted_tcp;
	const uint16_t icmp_len = sizeof(*icmp) + sizeof(*quoted_ip4) + 8;
	const uint16_t packet_len = 14 + sizeof(*ip4) + icmp_len;

	assert(pkt);
	data = iip_ops_pkt_get_data(pkt, opaque);
	memset(data, 0, packet_len);
	iip_ops_pkt_set_len(pkt, packet_len, opaque);
	iip_ops_l2_hdr_craft(pkt, f->peer_mac, f->local_mac,
			ii_htons(0x0800), opaque);

	ip4 = PB_IP4(pkt);
	ip4->vl = (4U << 4) | (sizeof(*ip4) / 4);
	ip4->len_be = ii_htons(sizeof(*ip4) + icmp_len);
	ip4->ttl = 64;
	ip4->proto = 1;
	ip4->src_be = ii_htonl(f->conn->dst_ip[0]);
	ip4->dst_be = ii_htonl(f->conn->src_ip[0]);

	icmp = PB_ICMP(pkt);
	icmp->type = type;
	icmp->code = code;
	quoted_ip4 = (struct iip_ip4_hdr *)PB_ICMP_DATA(pkt);
	quoted_ip4->vl = (4U << 4) | (sizeof(*quoted_ip4) / 4);
	quoted_ip4->len_be = ii_htons(sizeof(*quoted_ip4) + sizeof(*quoted_tcp));
	quoted_ip4->ttl = 64;
	quoted_ip4->proto = 6;
	quoted_ip4->src_be = ii_htonl(f->conn->src_ip[0]);
	quoted_ip4->dst_be = ii_htonl(f->conn->dst_ip[0]);
	quoted_tcp = (struct iip_tcp_hdr *)((uint8_t *)quoted_ip4 + sizeof(*quoted_ip4));
	quoted_tcp->src_be = ii_htons(f->conn->src_port);
	quoted_tcp->dst_be = ii_htons(f->conn->dst_port);
    if (f->icmp_quote_valid) memcpy(quoted_ip4, f->icmp_quote, sizeof(f->icmp_quote));

	update_ip4_checksum(pkt);
	update_icmp_checksum(pkt);
	return pkt;
}

static void fixture_run_timers(struct fixture *f)
{
	uint32_t next_us = UINT32_MAX;
	assert(test_api_run(f->ws, f->local_mac, ii_htonl(f->conn->src_ip[0]),
			NULL, 0, &next_us, &f->state) == 0);
}

/* Advance simulated time and let the stack process its timers once. */
static void fixture_advance_ms(struct fixture *f, uint64_t elapsed_ms)
{
    fake_clock_advance_ms(&f->state, elapsed_ms);
    fixture_run_timers(f);
}

/* One incoming byte at sequence zero; callers decide how to modify/verify it. */
static void *fixture_input_packet(struct fixture *f)
{
    static const uint8_t payload[] = { 0 };
    struct tcp_packet_spec spec;
    fixture_incoming_spec(f, &spec, 0, payload, sizeof(payload));
    return build_tcp_packet(&spec, &f->state);
}

static int wait_test_child(pid_t child, unsigned int timeout_ms)
{
	unsigned int waited_ms;
	int status = 0;
	for (waited_ms = 0; waited_ms < timeout_ms; waited_ms += 10) {
		pid_t result = waitpid(child, &status, WNOHANG);
		assert(result >= 0);
		if (result == child) {
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
				return 1;
			if (WIFSIGNALED(status))
				fprintf(stderr,
					"FAILED CHILD: pid=%ld terminated by signal=%d\n",
					(long)child, WTERMSIG(status));
			else if (WIFEXITED(status))
				fprintf(stderr,
					"FAILED CHILD: pid=%ld exited with status=%d\n",
					(long)child, WEXITSTATUS(status));
			else
				fprintf(stderr,
					"FAILED CHILD: pid=%ld ended with wait status=0x%x\n",
					(long)child, status);
			return 0;
		}
		usleep(10 * 1000);
	}
	fprintf(stderr, "FAILED CHILD: pid=%ld timed out after %u ms\n",
			(long)child, timeout_ms);
	kill(child, SIGKILL);
	assert(waitpid(child, &status, 0) == child);
	return 0;
}

static void fixture_prepare_sender(struct fixture *f)
{
	fake_clock_set_ns(&f->state, 1000000000ULL);
	f->conn->peer_win = 65535;
	f->conn->ws = 0;
	f->conn->acked_seq = f->conn->seq;
	f->conn->ack_seq_xmitted = f->conn->ack_seq;
}

static int fixture_send_data(struct fixture *f, uint16_t len)
{
	void *payload = iip_ops_pkt_alloc(&f->state);
	if (!payload)
		return 0;
	memset(iip_ops_pkt_get_data(payload, &f->state), 0x5a, len);
	iip_ops_pkt_set_len(payload, len, &f->state);
	test_api_send(f->ws, f->conn, payload, 0, &f->state);
	fixture_run_timers(f);
	return test_ring_end(f->ws, &f->conn->sent_ring, 0) != NULL;
}

/* Positive ICMP errors quote an actual, outstanding wire segment. */
static int fixture_prepare_icmp(struct fixture *f)
{
    fixture_prepare_sender(f);
    if (!fixture_send_data(f, 1) || !f->state.out_cnt) return 0;
    void *pkt = f->state.out[0];
    if (PB_IP4_HDR_LEN(pkt) != 20) return 0;
    memcpy(f->icmp_quote, PB_IP4(pkt), sizeof(f->icmp_quote));
    f->icmp_quote_valid = 1;
    free_output(&f->state);
    test_event_log_clear(&f->state);
    return 1;
}

static void *fixture_oversized_tcp_payload(struct fixture *f)
{
	void *payload = iip_ops_pkt_alloc(&f->state);

	if (payload)
		iip_ops_pkt_set_len(payload, (uint16_t)(f->conn->mss + 1),
				&f->state);
	return payload;
}

/* Enqueue succeeds before serialization in the current API.  Snapshot only
 * after enqueue, and inject failure into the operation that can reject capacity. */
static uint16_t fixture_transmit_with_capacity_failure(struct fixture *f,
		struct ii_pb *p, uint16_t failing_capacity)
{
	/* Existing input payload keeps its real capacity.  The first output
	 * segment fits; the next allocation exercises failure after partial work. */
	packet_capacity_exempt_payload = p->part_pkt[0];
	packet_capacity_sequence_begin(2048, failing_capacity);
	enum iip_rc rc = ii_tcp_xmit_queued_data_one(f->ws,
		test_conn_id(f->ws, f->conn), (uint32_t)(p - f->ws->pbs.array),
		0, p->tcp.payload_len, &f->state);
	packet_capacity_sequence_end();
	packet_capacity_exempt_payload = NULL;
	return rc == IIP_ERR_OK ? 0 : UINT16_MAX;
}


/* Passive and active TCP Fast Open scenarios.
 * Included in dependency order by test_tcp.h.
 */

static enum result test_tcp_fast_open_passive_data(const char **why)
{
	static const uint8_t payload[] = { 0x31, 0x32, 0x33, 0x34 };
	const uint16_t cookie_peer_port_be = ii_htons(21033);
	const uint16_t peer_port_be = ii_htons(21034);
	const uint32_t syn_seq = 100;
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *child;
	void *syn_ack, *cookie_option;
	uint8_t cookie[16];
	uint8_t cookie_len;
	uint32_t syn_ack_seq;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.state.accept_arbitrary_payload = 1;
	if (!test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(f.conn->src_port), 0, 0, NULL)) {
		*why = "could not create the passive OPEN";
		return RESULT_FAIL;
	}

	/* First obtain a server-generated cookie with an empty kind-34 option. */
	fixture_incoming_spec(&f, &spec, syn_seq, NULL, 0);
	spec.src_port_be = cookie_peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_option(&spec, 34, NULL, 0);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	syn_ack = output_nth_ethertype(&f.state, 0x0800, 0);
	cookie_option = syn_ack ? option_find(syn_ack, 34) : NULL;
	if (!syn_ack || !PB_TCP_HDR_HAS_SYN(syn_ack) ||
			!PB_TCP_HDR_HAS_ACK(syn_ack) || !cookie_option ||
			((uint8_t *)cookie_option)[1] < 6 ||
			((uint8_t *)cookie_option)[1] > sizeof(cookie) + 2) {
		*why = "cookie request did not produce a Fast Open cookie";
		return RESULT_FAIL;
	}
	cookie_len = ((uint8_t *)cookie_option)[1] - 2;
	memcpy(cookie, (uint8_t *)cookie_option + 2, cookie_len);
	free_output(&f.state);
	test_event_log_clear(&f.state);

	/*
	 * Reuse the issued cookie on a new connection.  A TFO-capable passive
	 * endpoint accepts and delivers the SYN data before the third ACK.
	 */
	fixture_incoming_spec(&f, &spec, syn_seq, payload, sizeof(payload));
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_option(&spec, 34, cookie, cookie_len);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	child = fixture_find_peer_port(&f, peer_port_be);
	syn_ack = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!child || child == f.conn || !syn_ack ||
			!PB_TCP_HDR_HAS_SYN(syn_ack) ||
			!PB_TCP_HDR_HAS_ACK(syn_ack)) {
		*why = "SYN data did not create a child and SYN+ACK";
		return RESULT_FAIL;
	}
	syn_ack_seq = ii_ntohl(PB_TCP(syn_ack)->seq_be);
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPTED) != 1 ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_PAYLOAD) != 1 ||
			f.state.payload_byte_count != sizeof(payload)) {
		*why = "SYN data was not accepted and delivered before the final ACK";
		return RESULT_FAIL;
	}
	free_output(&f.state);

	/* A retransmitted SYN must not repeat accept or payload delivery. */
	fixture_incoming_spec(&f, &spec, syn_seq, payload, sizeof(payload));
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_option(&spec, 34, cookie, cookie_len);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPTED) != 1 ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_PAYLOAD) != 1 ||
			f.state.payload_byte_count != sizeof(payload)) {
		*why = "retransmitted SYN data was delivered more than once";
		return RESULT_FAIL;
	}
	free_output(&f.state);

	/* Complete the handshake without repeating the early callbacks. */
	fixture_incoming_spec(&f, &spec, syn_seq + 1 + sizeof(payload),
			NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.ack_seq = syn_ack_seq + 1;
	spec.tcp_flags = TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (child->state != II_TCP_STATE_ESTABLISHED ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_ACCEPTED) != 1 ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_PAYLOAD) != 1 ||
			f.state.payload_byte_count != sizeof(payload)) {
		*why = "final ACK did not preserve one early accept and delivery";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}

enum fastopen_rejected_option {
	FASTOPEN_REJECT_NO_OPTION,
	FASTOPEN_REJECT_REQUEST,
	FASTOPEN_REJECT_INVALID_COOKIE,
	FASTOPEN_REJECT_DUPLICATE_COOKIE,
};

static int test_fastopen_rejected_syn_data_case(
		enum fastopen_rejected_option option, const char **why)
{
	static const uint8_t payload[] = { 0x41, 0x42, 0x43, 0x44 };
	const uint16_t peer_port_be =
			ii_htons((uint16_t)(21100 + option));
	const uint32_t syn_seq = 300;
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *child;
	void *syn_ack;
	uint8_t cookie[16];
	uint8_t cookie_len;

	if (!fixture_init(&f))
		return 0;
	f.state.accept_arbitrary_payload = 1;
	if (!test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(f.conn->src_port), 0, 0, NULL)) {
		*why = "could not create the passive OPEN";
		return 0;
	}

	fixture_incoming_spec(&f, &spec, syn_seq, payload, sizeof(payload));
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	if (option == FASTOPEN_REJECT_REQUEST) {
		tcp_packet_add_option(&spec, 34, NULL, 0);
	} else if (option == FASTOPEN_REJECT_INVALID_COOKIE) {
		test_tcp_fastopen_request(spec.src_ip_be, spec.dst_ip_be,
				cookie, &cookie_len);
		assert(cookie_len);
		cookie[0] ^= 0xffU;
		tcp_packet_add_option(&spec, 34, cookie, cookie_len);
	} else if (option == FASTOPEN_REJECT_DUPLICATE_COOKIE) {
		test_tcp_fastopen_request(spec.src_ip_be, spec.dst_ip_be,
				cookie, &cookie_len);
		assert(cookie_len);
		tcp_packet_add_option(&spec, 34, cookie, cookie_len);
		tcp_packet_add_option(&spec, 34, cookie, cookie_len);
	}
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));

	child = fixture_find_peer_port(&f, peer_port_be);
	syn_ack = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!child || child == f.conn || !syn_ack ||
			!PB_TCP_HDR_HAS_SYN(syn_ack) ||
			!PB_TCP_HDR_HAS_ACK(syn_ack)) {
		*why = "rejected SYN data did not produce a child and SYN+ACK";
		return 0;
	}
	if (ii_ntohl(PB_TCP(syn_ack)->ack_seq_be) != syn_seq + 1 ||
			child->seq_next_expected != syn_seq + 1) {
		*why = "rejected SYN data was consumed or acknowledged";
		return 0;
	}
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPTED) ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_PAYLOAD) ||
			f.state.payload_byte_count) {
		*why = "rejected SYN data reached the application";
		return 0;
	}
	free_output(&f.state);
	return 1;
}

static enum result test_tcp_fast_open_rejects_unvalidated_data(
		const char **why)
{
	if (!test_fastopen_rejected_syn_data_case(
			FASTOPEN_REJECT_NO_OPTION, why))
		return RESULT_FAIL;
	if (!test_fastopen_rejected_syn_data_case(
			FASTOPEN_REJECT_REQUEST, why))
		return RESULT_FAIL;
	if (!test_fastopen_rejected_syn_data_case(
			FASTOPEN_REJECT_INVALID_COOKIE, why))
		return RESULT_FAIL;
	return RESULT_PASS;
}

static enum result test_tcp_fast_open_rejects_duplicate_option(
		const char **why)
{
	return test_fastopen_rejected_syn_data_case(
			FASTOPEN_REJECT_DUPLICATE_COOKIE, why) ?
			RESULT_PASS : RESULT_FAIL;
}

static enum result test_tcp_fast_open_cookie_generation_disabled(
		const char **why)
{
	const uint16_t peer_port_be = ii_htons(21110);
	struct fixture f;
	struct tcp_packet_spec spec;
	void *syn_ack;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	if (!test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(f.conn->src_port), 0, 0, NULL)) {
		*why = "could not create the passive OPEN";
		return RESULT_FAIL;
	}

	fixture_incoming_spec(&f, &spec, 400, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_option(&spec, 34, NULL, 0);
	_fastopen_cookie_len = 0;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	_fastopen_cookie_len = 16;

	syn_ack = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!syn_ack || !PB_TCP_HDR_HAS_SYN(syn_ack) ||
			!PB_TCP_HDR_HAS_ACK(syn_ack)) {
		*why = "disabled cookie generation did not produce a SYN+ACK";
		return RESULT_FAIL;
	}
	if (option_find(syn_ack, 34)) {
		*why = "disabled cookie generation emitted a Fast Open option";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}

static void *fastopen_test_payload(struct test_state *state,
		const uint8_t *data, uint16_t len)
{
	void *pkt = iip_ops_pkt_alloc(state);
	if (!pkt)
		return NULL;
	memcpy(iip_ops_pkt_get_data(pkt, state), data, len);
	iip_ops_pkt_set_len(pkt, len, state);
	return pkt;
}

static struct ii_tcp_conn *fixture_find_local_port(struct fixture *f,
		uint16_t local_port_be)
{
	for (uint32_t i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
		struct ii_tcp_conn *conn = &f->ws->tcp_conns.array[i];
		if (conn->state != II_TCP_STATE_CLOSED && ii_htons(conn->src_port) == local_port_be)
			return conn;
	}
	return NULL;
}

static enum result test_tcp_fast_open_active_cookie_and_data(const char **why)
{
	static const uint8_t payload[] = { 0x61, 0x62, 0x63, 0x64 };
	const uint16_t cookie_port_be = ii_htons(21200);
	const uint16_t data_port_be = ii_htons(21201);
	const uint16_t peer_port_be = ii_htons(22000);
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *conn;
	void *syn, *syn_ack, *syn_data, *payload_pkt;
	uint8_t cookie[16], cookie_len, *option;
	uint32_t client_isn;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	memset(&_fastopen_saved_cookie, 0, sizeof(_fastopen_saved_cookie));

	/* Obtain and save a cookie delivered in a SYN+ACK. */
	if (test_api_connect(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]),
			cookie_port_be, f.peer_mac, ii_htonl(f.conn->dst_ip[0]),
			peer_port_be, &f.state)) {
		*why = "ordinary active OPEN for cookie acquisition failed";
		return RESULT_FAIL;
	}
	fixture_run_timers(&f);
	syn = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!syn || !PB_TCP_HDR_HAS_SYN(syn) || PB_TCP_HDR_HAS_ACK(syn)) {
		*why = "cookie acquisition did not emit a SYN";
		return RESULT_FAIL;
	}
	client_isn = ii_ntohl(PB_TCP(syn)->seq_be);
	test_tcp_fastopen_request(ii_htonl(f.conn->src_ip[0]), ii_htonl(f.conn->dst_ip[0]),
			cookie, &cookie_len);
	tcp_packet_spec_init(&spec);
	memcpy(spec.src_mac, f.peer_mac, sizeof(spec.src_mac));
	memcpy(spec.dst_mac, f.local_mac, sizeof(spec.dst_mac));
	spec.src_ip_be = ii_htonl(f.conn->dst_ip[0]);
	spec.dst_ip_be = ii_htonl(f.conn->src_ip[0]);
	spec.src_port_be = peer_port_be;
	spec.dst_port_be = cookie_port_be;
	spec.seq = 500;
	spec.ack_seq = client_isn + 1;
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	tcp_packet_add_option(&spec, 34, cookie, cookie_len);
	syn_ack = build_tcp_packet(&spec, &f.state);
	fixture_deliver(&f, syn_ack);
	conn = fixture_find_local_port(&f, cookie_port_be);
	if (!conn || conn->state != II_TCP_STATE_ESTABLISHED ||
			_fastopen_saved_cookie.len != cookie_len ||
			_fastopen_saved_cookie.peer_ip4_be != ii_htonl(f.conn->dst_ip[0]) ||
			_fastopen_saved_cookie.local_ip4_be != ii_htonl(f.conn->src_ip[0]) ||
			memcmp(_fastopen_saved_cookie.buf, cookie, cookie_len)) {
		*why = "SYN+ACK Fast Open cookie was not saved by the application";
		return RESULT_FAIL;
	}
	free_output(&f.state);

	/* Reuse the saved cookie and verify active SYN data is acknowledged. */
	payload_pkt = fastopen_test_payload(&f.state, payload, sizeof(payload));
	if (!payload_pkt || test_api_fast_open(f.ws, f.local_mac,
			ii_htonl(f.conn->src_ip[0]), data_port_be, f.peer_mac,
			ii_htonl(f.conn->dst_ip[0]), peer_port_be, payload_pkt,
			_fastopen_saved_cookie.buf, _fastopen_saved_cookie.len,
			&f.state)) {
		*why = "active Fast Open with the saved cookie failed";
		return RESULT_FAIL;
	}
	fixture_run_timers(&f);
	syn_data = output_nth_ethertype(&f.state, 0x0800, 0);
	option = syn_data ? option_find(syn_data, 34) : NULL;
	if (!syn_data || !PB_TCP_HDR_HAS_SYN(syn_data) ||
			PB_TCP_PAYLOAD_LEN(syn_data) != sizeof(payload) ||
			memcmp(PB_TCP_PAYLOAD(syn_data), payload, sizeof(payload)) ||
			!option || option[1] != cookie_len + 2 ||
			memcmp(&option[2], cookie, cookie_len) ||
			!ip4_checksum_valid(syn_data) || !checksum_valid(syn_data)) {
		*why = "active Fast Open SYN did not contain valid cookie and data";
		return RESULT_FAIL;
	}
	client_isn = ii_ntohl(PB_TCP(syn_data)->seq_be);
	free_output(&f.state);

	tcp_packet_spec_init(&spec);
	memcpy(spec.src_mac, f.peer_mac, sizeof(spec.src_mac));
	memcpy(spec.dst_mac, f.local_mac, sizeof(spec.dst_mac));
	spec.src_ip_be = ii_htonl(f.conn->dst_ip[0]);
	spec.dst_ip_be = ii_htonl(f.conn->src_ip[0]);
	spec.src_port_be = peer_port_be;
	spec.dst_port_be = data_port_be;
	spec.seq = 600;
	spec.ack_seq = client_isn + 1 + sizeof(payload);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	conn = fixture_find_local_port(&f, data_port_be);
	if (!conn || conn->state != II_TCP_STATE_ESTABLISHED ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CONNECTED) < 2) {
		*why = "acknowledged active Fast Open did not establish the connection";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}

static enum result test_tcp_fast_open_active_rejection_fallback(
		const char **why)
{
	static const uint8_t payload[] = { 0x71, 0x72, 0x73, 0x74 };
	const uint16_t local_port_be = ii_htons(21202);
	const uint16_t peer_port_be = ii_htons(22000);
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *conn;
	void *payload_pkt, *syn_data, *fallback;
	uint8_t cookie[16], cookie_len;
	uint32_t client_isn;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_tcp_fastopen_request(ii_htonl(f.conn->src_ip[0]), ii_htonl(f.conn->dst_ip[0]),
			cookie, &cookie_len);
	payload_pkt = fastopen_test_payload(&f.state, payload, sizeof(payload));
	if (!payload_pkt || test_api_fast_open(f.ws, f.local_mac,
			ii_htonl(f.conn->src_ip[0]), local_port_be, f.peer_mac,
			ii_htonl(f.conn->dst_ip[0]), peer_port_be, payload_pkt, cookie,
			cookie_len, &f.state)) {
		*why = "active Fast Open setup for rejection failed";
		return RESULT_FAIL;
	}
	fixture_run_timers(&f);
	syn_data = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!syn_data || !PB_TCP_HDR_HAS_SYN(syn_data)) {
		*why = "active Fast Open did not emit SYN data";
		return RESULT_FAIL;
	}
	client_isn = ii_ntohl(PB_TCP(syn_data)->seq_be);
	free_output(&f.state);

	/* ACK only the SYN, forcing the data to be retransmitted without SYN. */
	tcp_packet_spec_init(&spec);
	memcpy(spec.src_mac, f.peer_mac, sizeof(spec.src_mac));
	memcpy(spec.dst_mac, f.local_mac, sizeof(spec.dst_mac));
	spec.src_ip_be = ii_htonl(f.conn->dst_ip[0]);
	spec.dst_ip_be = ii_htonl(f.conn->src_ip[0]);
	spec.src_port_be = peer_port_be;
	spec.dst_port_be = local_port_be;
	spec.seq = 700;
	spec.ack_seq = client_isn + 1;
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fallback = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!fallback) {
		fixture_run_timers(&f);
		fallback = output_nth_ethertype(&f.state, 0x0800, 0);
	}
	conn = fixture_find_local_port(&f, local_port_be);
	if (!conn || conn->state != II_TCP_STATE_ESTABLISHED ||
			!fallback || PB_TCP_HDR_HAS_SYN(fallback) ||
			ii_ntohl(PB_TCP(fallback)->seq_be) != client_isn + 1 ||
			PB_TCP_PAYLOAD_LEN(fallback) != sizeof(payload) ||
			memcmp(PB_TCP_PAYLOAD(fallback), payload, sizeof(payload)) ||
			!ip4_checksum_valid(fallback) || !checksum_valid(fallback)) {
		*why = "rejected SYN data was not retransmitted as valid normal data";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}


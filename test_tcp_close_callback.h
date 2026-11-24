/* Close-notification contract of the native callback API.
 * Included by test_tcp.h after the connection and Fast Open scenarios.
 *
 * IIP_OPS_TCP_CLOSED() is delivered exactly once for a connection that the
 * application owns -- one returned by a successful connect or reported
 * through IIP_OPS_TCP_ACCEPTED() -- and never for a connection the
 * application has not been told about (a passive open still in
 * SYN-RECEIVED, or a connect that returned an error).
 */

static unsigned int close_cb_count(struct fixture *f, unsigned int type)
{
	return test_event_count(&f->state, TEST_EVENT_CALLBACK, type);
}

/* Passive SYN-RECEIVED + RST: no ACCEPTED, so no CLOSED. */
static enum result close_cb_passive_rst(const char **why)
{
	struct fixture f;
	struct passive_syn_ack sa;
	struct tcp_packet_spec spec;
	const uint16_t peer_port_be = ii_htons(21100);

	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	TEST_REQUIRE(why, fixture_passive_open(&f, peer_port_be, -1, 0, 0, &sa) &&
			sa.conn->state == II_TCP_STATE_SYN_RECVD,
			"passive SYN did not create a SYN-RECEIVED child");
	fixture_incoming_spec(&f, &spec, 101, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_RST;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	free_output(&f.state);
	TEST_REQUIRE(why, sa.conn->state == II_TCP_STATE_CLOSED,
			"RST in passive SYN-RECEIVED did not close the child (state=%u)",
			sa.conn->state);
	TEST_REQUIRE(why, close_cb_count(&f, TEST_CALLBACK_ACCEPTED) == 0 &&
			close_cb_count(&f, TEST_CALLBACK_CLOSED) == 0,
			"unaccepted passive open: accepted=%u closed=%u; expected 0/0",
			close_cb_count(&f, TEST_CALLBACK_ACCEPTED),
			close_cb_count(&f, TEST_CALLBACK_CLOSED));
	return RESULT_PASS;
}

/* Passive SYN-RECEIVED, SYN,ACK retransmissions exhausted: no CLOSED. */
static enum result close_cb_passive_timeout(const char **why)
{
	struct fixture f;
	struct passive_syn_ack sa;
	const uint16_t peer_port_be = ii_htons(21101);
	uint64_t started_ns;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	TEST_REQUIRE(why, fixture_passive_open(&f, peer_port_be, -1, 0, 0, &sa) &&
			sa.conn->state == II_TCP_STATE_SYN_RECVD,
			"passive SYN did not create a SYN-RECEIVED child");
	started_ns = f.state.now_ns;
	while (sa.conn->state == II_TCP_STATE_SYN_RECVD &&
			f.state.now_ns - started_ns <= 3600ULL * 1000000000ULL) {
		uint32_t rto_ms = sa.conn->rto_ms;
		TEST_REQUIRE(why, rto_ms, "no retransmission timer for the SYN,ACK");
		fixture_advance_ms(&f, (uint64_t)rto_ms + 1);
		free_output(&f.state);
	}
	TEST_REQUIRE(why, !f.state.event_dropped,
			"harness error: %u events dropped", f.state.event_dropped);
	TEST_REQUIRE(why, sa.conn->state == II_TCP_STATE_CLOSED,
			"SYN-RECEIVED child was not abandoned within one hour (state=%u)",
			sa.conn->state);
	TEST_REQUIRE(why, close_cb_count(&f, TEST_CALLBACK_ACCEPTED) == 0 &&
			close_cb_count(&f, TEST_CALLBACK_CLOSED) == 0,
			"abandoned passive open: accepted=%u closed=%u; expected 0/0",
			close_cb_count(&f, TEST_CALLBACK_ACCEPTED),
			close_cb_count(&f, TEST_CALLBACK_CLOSED));
	return RESULT_PASS;
}

/* Accepted passive open + RST: exactly one CLOSED. */
static enum result close_cb_accepted_rst(const char **why)
{
	struct fixture f;
	struct passive_syn_ack sa;
	struct tcp_packet_spec spec;
	const uint16_t peer_port_be = ii_htons(21102);

	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	TEST_REQUIRE(why, fixture_passive_open(&f, peer_port_be, -1, 0, 1, &sa),
			"passive handshake did not reach ESTABLISHED");
	TEST_REQUIRE(why, close_cb_count(&f, TEST_CALLBACK_ACCEPTED) == 1,
			"handshake produced %u accepted callback(s); expected 1",
			close_cb_count(&f, TEST_CALLBACK_ACCEPTED));
	fixture_incoming_spec(&f, &spec, 101, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_RST;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	free_output(&f.state);
	TEST_REQUIRE(why, sa.conn->state == II_TCP_STATE_CLOSED &&
			close_cb_count(&f, TEST_CALLBACK_CLOSED) == 1,
			"accepted connection + RST: state=%u closed=%u; expected CLOSED/1",
			sa.conn->state, close_cb_count(&f, TEST_CALLBACK_CLOSED));
	return RESULT_PASS;
}

/* connect() that returns an error: no CLOSED. */
static enum result close_cb_connect_failure(const char **why)
{
	struct fixture f;
	uint8_t cookie[sizeof(((struct ii_tcp_conn *)0)->fastopen_cookie.buf) + 1];
	uint16_t rc;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	memset(cookie, 0x5a, sizeof(cookie));
	test_event_log_clear(&f.state);
	rc = test_api_fast_open(f.ws, f.local_mac, ii_htonl(0xc0000201U),
			ii_htons(10100), f.peer_mac, ii_htonl(0xc6336402U),
			ii_htons(20100), NULL, cookie, (uint8_t)sizeof(cookie), &f.state);
	TEST_REQUIRE(why, rc == UINT16_MAX,
			"connect with an oversized cookie did not fail");
	fixture_advance_ms(&f, 10);
	fixture_run_timers(&f);
	free_output(&f.state);
	TEST_REQUIRE(why, close_cb_count(&f, TEST_CALLBACK_CLOSED) == 0,
			"failed connect produced %u closed callback(s); expected 0",
			close_cb_count(&f, TEST_CALLBACK_CLOSED));
	return RESULT_PASS;
}

static enum result test_close_callback_ownership(const char **why)
{
	enum result r;
	if ((r = close_cb_passive_rst(why)) != RESULT_PASS) return r;
	if ((r = close_cb_passive_timeout(why)) != RESULT_PASS) return r;
	if ((r = close_cb_accepted_rst(why)) != RESULT_PASS) return r;
	return close_cb_connect_failure(why);
}

/* TFO: ACCEPTED is reported in SYN-RECEIVED, so an RST before the final
 * ACK must still produce exactly one CLOSED. */
static enum result test_tcp_fast_open_close_callback(const char **why)
{
	static const uint8_t payload[] = { 0x41, 0x42, 0x43, 0x44 };
	const uint16_t cookie_peer_port_be = ii_htons(21133);
	const uint16_t peer_port_be = ii_htons(21134);
	const uint32_t syn_seq = 100;
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *child;
	void *syn_ack, *cookie_option;
	uint8_t cookie[16];
	uint8_t cookie_len;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.state.accept_arbitrary_payload = 1;
	TEST_REQUIRE(why, test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(f.conn->src_port), 0, 0, NULL),
			"could not create the passive OPEN");
	fixture_incoming_spec(&f, &spec, syn_seq, NULL, 0);
	spec.src_port_be = cookie_peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_option(&spec, 34, NULL, 0);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	syn_ack = output_nth_ethertype(&f.state, 0x0800, 0);
	cookie_option = syn_ack ? option_find(syn_ack, 34) : NULL;
	TEST_REQUIRE(why, cookie_option &&
			((uint8_t *)cookie_option)[1] >= 6 &&
			((uint8_t *)cookie_option)[1] <= sizeof(cookie) + 2,
			"cookie request did not produce a Fast Open cookie");
	cookie_len = ((uint8_t *)cookie_option)[1] - 2;
	memcpy(cookie, (uint8_t *)cookie_option + 2, cookie_len);
	free_output(&f.state);
	test_event_log_clear(&f.state);

	fixture_incoming_spec(&f, &spec, syn_seq, payload, sizeof(payload));
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_option(&spec, 34, cookie, cookie_len);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	child = fixture_find_peer_port(&f, peer_port_be);
	TEST_REQUIRE(why, child && child != f.conn &&
			child->state == II_TCP_STATE_SYN_RECVD &&
			close_cb_count(&f, TEST_CALLBACK_ACCEPTED) == 1,
			"SYN data was not accepted in SYN-RECEIVED");
	free_output(&f.state);

	fixture_incoming_spec(&f, &spec, syn_seq + 1 + sizeof(payload), NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_RST;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	free_output(&f.state);
	TEST_REQUIRE(why, child->state == II_TCP_STATE_CLOSED &&
			close_cb_count(&f, TEST_CALLBACK_CLOSED) == 1,
			"TFO-accepted child + RST: state=%u closed=%u; expected CLOSED/1",
			child->state, close_cb_count(&f, TEST_CALLBACK_CLOSED));
	return RESULT_PASS;
}

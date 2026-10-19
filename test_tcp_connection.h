/* Initial sequence numbers, connection states, handshakes, and MSS.
 * Included in dependency order by test_tcp.h.
 */

static struct ii_tcp_conn *fixture_find_peer_port(struct fixture *f,
		uint16_t peer_port_be);

/* Actively open the fixture's peer at peer_port and return the SYN's ISS. */
static int isn_probe_open(struct fixture *f, uint16_t peer_port_be,
		uint32_t *iss)
{
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *conn;
	void *syn;

	free_output(&f->state);
	if (test_tcp_active_open(f->ws, f->local_mac,
			&(uint32_t){ ii_htonl(f->conn->src_ip[0]) }, ii_htons(15000),
			f->peer_mac, ii_htonl(f->conn->dst_ip[0]), peer_port_be,
			&f->state) == 0xffff)
		return 0;
	fixture_run_timers(f);
	syn = output_nth_ethertype(&f->state, 0x0800, 0);
	conn = fixture_find_peer_port(f, peer_port_be);
	if (!syn || !conn || !PB_TCP_HDR_HAS_SYN(syn))
		return 0;
	*iss = ii_ntohl(PB_TCP(syn)->seq_be);
	free_output(&f->state);
	/* Refuse the attempt so the same 4-tuple can be reused. */
	fixture_incoming_spec(f, &spec, 0, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.dst_port_be = ii_htons(15000);
	spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
	spec.ack_seq = *iss + 1;
	fixture_deliver(f, build_tcp_packet(&spec, &f->state));
	fixture_run_timers(f);
	free_output(&f->state);
	return fixture_find_peer_port(f, peer_port_be) == NULL ||
		conn->state == II_TCP_STATE_CLOSED;
}

/*
 * MUST-8 (RFC 9293 Section 3.4.1): the ISN generator is driven by a clock,
 * ISN = M + F(...), where F is constant for a given 4-tuple.  Observe the
 * ISS of SYNs sent for the same 4-tuple at different times on the wire
 * rather than inspecting the implementation's internal counter: a later
 * attempt must use a later ISS in sequence space.
 */
static enum result test_clock_driven_isn(const char **why)
{
	struct fixture f;
	const uint16_t peer_port_be = ii_htons(26000);
	uint32_t first, second, third;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	fixture_run_timers(&f);
	if (!isn_probe_open(&f, peer_port_be, &first))
		return RESULT_FAIL;
	fake_clock_advance_sec(&f.state, 10);
	fixture_run_timers(&f);
	if (!isn_probe_open(&f, peer_port_be, &second))
		return RESULT_FAIL;
	fake_clock_advance_sec(&f.state, 10);
	fixture_run_timers(&f);
	if (!isn_probe_open(&f, peer_port_be, &third))
		return RESULT_FAIL;
	if (second - first == 0 || second - first >= 0x80000000U ||
			third - second == 0 || third - second >= 0x80000000U) {
		*why = "the ISS for the same 4-tuple did not advance with the clock";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_isn_prf_security(const char **why)
{
	const uint32_t local_ip_be = ii_htonl(0xc0000201U);
	const uint32_t peer_ip_be = ii_htonl(0xc6336402U);
	const uint16_t local_port_be = ii_htons(10000);
	const uint16_t peer_port_be = ii_htons(20000);
	uint8_t saved_key[sizeof(_iss_key)];
	uint8_t key_a[sizeof(_iss_key)];
	uint8_t key_b[sizeof(_iss_key)];
	uint32_t base;
	uint32_t other_key;
	struct fixture f;
	void *syn = NULL;
	unsigned int i;
	int ok = 1;
	(void)why;

	memcpy(saved_key, _iss_key, sizeof(saved_key));
	for (i = 0; i < sizeof(key_a); i++) {
		key_a[i] = (uint8_t)i;
		key_b[i] = (uint8_t)(0xa5U ^ i);
	}

	memcpy(_iss_key, key_a, sizeof(_iss_key));
	base = iip_ops_tcp_iss_off(local_ip_be, peer_ip_be,
			local_port_be, peer_port_be);
	/* Behavioral smoke test, not a proof of cryptographic PRF security.
	 * A particular hash and serialization are not RFC requirements. */
	ok &= iip_ops_tcp_iss_off(local_ip_be, peer_ip_be,
			local_port_be, peer_port_be) == base;
	ok &= iip_ops_tcp_iss_off(ii_htonl(0xc0000202U), peer_ip_be,
			local_port_be, peer_port_be) != base;
	ok &= iip_ops_tcp_iss_off(local_ip_be, ii_htonl(0xc6336403U),
			local_port_be, peer_port_be) != base;
	ok &= iip_ops_tcp_iss_off(local_ip_be, peer_ip_be,
			ii_htons(10001), peer_port_be) != base;
	ok &= iip_ops_tcp_iss_off(local_ip_be, peer_ip_be,
			local_port_be, ii_htons(20001)) != base;

	memcpy(_iss_key, key_b, sizeof(_iss_key));
	other_key = iip_ops_tcp_iss_off(local_ip_be, peer_ip_be,
			local_port_be, peer_port_be);
	ok &= other_key != base;

	/* Verify that connection initialization and the emitted SYN use M + F(). */
	memcpy(_iss_key, key_a, sizeof(_iss_key));
	if (!fixture_init(&f)) {
		ok = 0;
	} else {
		uint32_t expected = f.ws->tcp.iss + base;
		ok &= f.conn->iss == expected;
		syn = fixture_packet(&f, 1, 0, 0);
		ok &= syn != NULL;
		if (syn) {
			ok &= PB_TCP_HDR_HAS_SYN(syn);
			ok &= ii_ntohl(PB_TCP(syn)->seq_be) == expected;
			iip_ops_pkt_free(syn, &f.state);
		}
	}

	memcpy(_iss_key, saved_key, sizeof(_iss_key));
	return ok ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_isn_blake2_profile(const char **why)
{
	uint8_t saved[sizeof(_iss_key)];
	unsigned int i;
	uint32_t value;
	if (!getenv("IIP_TEST_BLAKE2_PROFILE")) {
		*why = "implementation-specific BLAKE2 serialization profile not selected";
		return RESULT_SKIP;
	}
	memcpy(saved, _iss_key, sizeof(saved));
	for (i = 0; i < sizeof(_iss_key); i++) _iss_key[i] = (uint8_t)i;
	value = iip_ops_tcp_iss_off(ii_htonl(0xc0000201U),
			ii_htonl(0xc6336402U), ii_htons(10000), ii_htons(20000));
	memcpy(_iss_key, saved, sizeof(saved));
	if (value != 0x353d3738U) {
		*why = "selected BLAKE2 serialization profile does not match its known answer";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int tcp_state_basic_flags_scenario(void)
{
	struct fixture ack, fin, rst;
	struct tcp_packet_spec spec;
	const struct test_event *payload_event;
	const uint8_t payload[] = { 0 };

	if (!fixture_init(&ack) || !fixture_init(&fin) || !fixture_init(&rst))
		return 0;
	fixture_incoming_spec(&ack, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags = TEST_TCP_ACK;
	fixture_deliver(&ack, build_tcp_packet(&spec, &ack.state));
	payload_event = test_event_nth(&ack.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 0);
	TEST_CONDITION(ack.conn->state == II_TCP_STATE_ESTABLISHED,
			"ACK+1-byte payload changed state: expected=ESTABLISHED actual=%u",
			ack.conn->state);
	TEST_CONDITION(ack.conn->seq_next_expected == 1,
			"ACK+1-byte payload set RCV.NXT=%u; expected 1",
			ack.conn->seq_next_expected);
	TEST_CONDITION(ack.state.payload_chunk_count == 1 && payload_event &&
				payload_event->value[0] == sizeof(payload),
			"ACK+1-byte payload delivery mismatch: chunks=%u first_chunk_len=%llu",
			ack.state.payload_chunk_count,
			(unsigned long long)(payload_event ? payload_event->value[0] : 0));

	fixture_incoming_spec(&fin, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_FIN | TEST_TCP_ACK;
	fixture_deliver(&fin, build_tcp_packet(&spec, &fin.state));
	TEST_CONDITION(fin.conn->state == II_TCP_STATE_CLOSE_WAIT,
			"ESTABLISHED + FIN|ACK ended in state=%u; expected CLOSE-WAIT",
			fin.conn->state);
	TEST_CONDITION(fin.state.close_wait.count == 1 &&
				fin.state.close_wait.conn == fin.conn,
			"FIN invoked CLOSE-WAIT hook %u time(s) with handle=%p; "
			"expected once with handle=%p",
			fin.state.close_wait.count, fin.state.close_wait.conn,
			(void *)fin.conn);

	fixture_incoming_spec(&rst, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
	fixture_deliver(&rst, build_tcp_packet(&spec, &rst.state));
	TEST_CONDITION(test_event_has_state_transition(&rst.state, rst.conn,
				II_TCP_STATE_ESTABLISHED, II_TCP_STATE_CLOSED),
			"ESTABLISHED + RST|ACK did not transition to CLOSED");
	TEST_CONDITION(test_event_count(&rst.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1,
			"ESTABLISHED + RST|ACK produced %u closed callback(s); expected 1",
			test_event_count(&rst.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED));
	return 1;
}

static int tcp_half_close_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_pb *fin;
	void *payload;
	const uint8_t data[] = { 0x48, 0x41, 0x4c, 0x46 };

	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_FIN | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.conn->state == II_TCP_STATE_CLOSE_WAIT,
			"half-close hook did not preserve CLOSE-WAIT: state=%u",
			f.conn->state);
	TEST_CONDITION(f.state.close_wait.count == 1 &&
				f.state.close_wait.conn == f.conn,
			"half-close hook invocation mismatch: count=%u handle=%p",
			f.state.close_wait.count, f.state.close_wait.conn);

	free_output(&f.state);
	payload = iip_ops_pkt_alloc(&f.state);
	TEST_CONDITION(payload != NULL,
			"failed to allocate payload for CLOSE-WAIT send");
	memcpy(iip_ops_pkt_get_data(payload, &f.state), data, sizeof(data));
	iip_ops_pkt_set_len(payload, sizeof(data), &f.state);
	TEST_CONDITION(test_api_send(f.ws, f.conn, payload, 0,
				&f.state) == 0 && test_ring_end(f.ws, &f.conn->tx_ring, 0) &&
				test_ring_end(f.ws, &f.conn->tx_ring, 0)->tcp.payload_len == sizeof(data),
			"CLOSE-WAIT send did not queue %zu payload bytes",
			sizeof(data));

	TEST_CONDITION(test_api_close(f.ws, f.conn, &f.state) == 0,
			"application close from CLOSE-WAIT failed");
	TEST_CONDITION(f.conn->state == II_TCP_STATE_LAST_ACK,
			"application close from CLOSE-WAIT ended in state=%u; "
			"expected LAST-ACK", f.conn->state);
	fin = test_ring_end(f.ws, &f.conn->tx_ring, 1);
	/* Transmit descriptors hold payload, not wire headers; inspect the
	 * descriptor flags rather than dereferencing part_pkt[0]. */
	TEST_CONDITION(fin && (fin->tcp.flags & II_TCP_FLAG_FIN),
			"application close from CLOSE-WAIT did not queue FIN");
	/* The FIN must be on the wire before the peer can acknowledge it. */
	fixture_run_timers(&f);

	fixture_incoming_spec(&f, &spec, 1, NULL, 0);
	spec.tcp_flags = TEST_TCP_ACK;
	spec.ack_seq = f.conn->fin_ack_seq;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1,
			"LAST-ACK completion produced %u closed callback(s); expected 1",
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED));
	return 1;
}

static int tcp_close_wait_auto_close_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *out;

	if (!fixture_init(&f))
		return 0;
	f.state.close_wait.auto_close = 1;
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_FIN | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.state.close_wait.count == 1,
			"automatic CLOSE-WAIT hook invoked %u time(s); expected once",
			f.state.close_wait.count);
	TEST_CONDITION(f.conn->state == II_TCP_STATE_LAST_ACK,
			"automatic CLOSE-WAIT close ended in state=%u; "
			"expected LAST-ACK", f.conn->state);
	TEST_CONDITION(output_count_ethertype(&f.state, 0x0800) == 1,
			"automatic CLOSE-WAIT close emitted %u IPv4 packets; "
			"expected one FIN|ACK",
			output_count_ethertype(&f.state, 0x0800));
	out = output_nth_ethertype(&f.state, 0x0800, 0);
	TEST_CONDITION(out && PB_TCP_HDR_HAS_FIN(out) &&
				PB_TCP_HDR_HAS_ACK(out),
			"automatic CLOSE-WAIT close did not emit one FIN|ACK");
	return 1;
}

static int tcp_payload_fin_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const struct test_event *payload_event;
	const uint8_t payload[] = { 0, 1, 2, 3 };

	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags = TEST_TCP_FIN | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	payload_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 0);
	TEST_CONDITION(f.state.payload_chunk_count == 1 && payload_event &&
				payload_event->value[0] == sizeof(payload) &&
				f.state.payload_byte_count == sizeof(payload),
			"payload+FIN delivered chunks=%u bytes=%llu first_len=%llu; "
			"expected one %zu-byte payload",
			f.state.payload_chunk_count,
			(unsigned long long)f.state.payload_byte_count,
			(unsigned long long)(payload_event ?
				payload_event->value[0] : 0), sizeof(payload));
	TEST_CONDITION(f.conn->state == II_TCP_STATE_CLOSE_WAIT &&
				f.state.close_wait.count == 1 &&
				f.state.close_wait.payload_chunk_count == 1,
			"payload+FIN did not enter CLOSE-WAIT exactly once: "
			"state=%u hook_count=%u payload_chunks_at_hook=%u",
			f.conn->state, f.state.close_wait.count,
			f.state.close_wait.payload_chunk_count);
	return 1;
}

static int tcp_simultaneous_close_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	if (!fixture_init(&f))
		return 0;
	fixture_prepare_sender(&f);
	uint32_t fin_seq = f.conn->seq;
	TEST_CONDITION(test_api_close(f.ws, f.conn, &f.state) == 0,
			"simultaneous close: local CLOSE failed");
	fixture_run_timers(&f);
	TEST_CONDITION(f.state.out_cnt && PB_TCP_HDR_HAS_FIN(f.state.out[0]),
			"simultaneous close: local FIN was not transmitted");
	free_output(&f.state);
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	/* RFC 9293 3.10.7.4: ACK is required; the crossing FIN cannot yet
	 * acknowledge our FIN. A FIN without ACK must instead be discarded. */
	spec.tcp_flags = TEST_TCP_FIN | TEST_TCP_ACK;
	spec.ack_seq = fin_seq;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.conn->state == II_TCP_STATE_CLOSING,
        "simultaneous close after FIN: expected state=%u, actual=%u",
        II_TCP_STATE_CLOSING, f.conn->state);
	free_output(&f.state);
	fixture_incoming_spec(&f, &spec, 1, NULL, 0);
	spec.tcp_flags = TEST_TCP_ACK;
	spec.ack_seq = fin_seq + 1U;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.conn->state == II_TCP_STATE_TIME_WAIT,
        "simultaneous close after ACK: expected state=%u, actual=%u",
        II_TCP_STATE_TIME_WAIT, f.conn->state);
    return 1;
}

static int tcp_sequence_wraparound_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const struct test_event *payload_event;
	const uint8_t payload[] = { 0, 1, 2, 3 };
	if (!fixture_init(&f))
		return 0;
	f.conn->seq_next_expected = UINT32_MAX - 1U;
	f.conn->ack_seq = UINT32_MAX - 1U;
	fixture_incoming_spec(&f, &spec, UINT32_MAX - 1U,
		payload, sizeof(payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	payload_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 0);
	TEST_CONDITION(f.conn->seq_next_expected == 2U,
        "sequence wrap: expected RCV.NXT=2, actual=%u", f.conn->seq_next_expected);
    TEST_CONDITION(f.state.payload_chunk_count == 1 &&
        f.state.payload_byte_count == sizeof(payload) && payload_event &&
        payload_event->value[0] == sizeof(payload),
        "sequence wrap: expected chunks=1 bytes=%zu event length=%zu, actual=%u/%llu/%llu",
        sizeof(payload), sizeof(payload), f.state.payload_chunk_count,
        (unsigned long long)f.state.payload_byte_count,
        (unsigned long long)(payload_event ? payload_event->value[0] : 0));
    return 1;
}

static int tcp_out_of_order_reassembly_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const struct test_event *first_payload_event;
	const struct test_event *second_payload_event;
	const uint8_t payload[] = { 0, 1, 2, 3 };
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 2, &payload[2], 2);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->seq_next_expected != 0 || f.state.payload_chunk_count != 0)
		return 0;
	free_output(&f.state);
	fixture_incoming_spec(&f, &spec, 0, &payload[0], 2);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	first_payload_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 0);
	second_payload_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 1);
	TEST_CONDITION(f.conn->seq_next_expected == 4,
			"out-of-order reassembly stopped at RCV.NXT=%u; expected 4",
			f.conn->seq_next_expected);
	TEST_CONDITION(f.state.payload_chunk_count == 2,
			"out-of-order reassembly delivered %u chunk(s); expected 2",
			f.state.payload_chunk_count);
	TEST_CONDITION(f.state.payload_byte_count == sizeof(payload),
			"out-of-order reassembly delivered %llu byte(s); expected %zu",
			(unsigned long long)f.state.payload_byte_count, sizeof(payload));
	TEST_CONDITION(first_payload_event && first_payload_event->value[0] == 2,
			"first reassembled payload chunk length=%llu; expected 2",
			(unsigned long long)(first_payload_event ?
				first_payload_event->value[0] : 0));
	TEST_CONDITION(second_payload_event && second_payload_event->value[0] == 2,
			"second reassembled payload chunk length=%llu; expected 2",
			(unsigned long long)(second_payload_event ?
				second_payload_event->value[0] : 0));
	return 1;
}

static int tcp_zero_window_update_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	if (!fixture_init(&f))
		return 0;
	fixture_prepare_sender(&f);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = 0;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->peer_win != 0)
		return 0;
	free_output(&f.state);
	spec.window = 4096;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.conn->peer_win == 4096;
}

static int tcp_state_transition_coverage_scenario(void)
{
	int ok = 1;

	/* Run every family even when an earlier transition exposes a defect. */
	TEST_ACCUMULATE(ok, tcp_state_basic_flags_scenario(),
			"basic ACK/FIN/RST handling failed: expected ESTABLISHED data delivery, CLOSE-WAIT on FIN, and CLOSED on RST");
	TEST_ACCUMULATE(ok, tcp_half_close_scenario(),
			"half-close failed: expected CLOSE-WAIT hook, delayed application close, LAST-ACK, and CLOSED");
	TEST_ACCUMULATE(ok, tcp_close_wait_auto_close_scenario(),
			"automatic CLOSE-WAIT close failed: expected one FIN|ACK and LAST-ACK");
	TEST_ACCUMULATE(ok, tcp_payload_fin_scenario(),
			"payload+FIN failed: expected payload delivery followed by one CLOSE-WAIT notification");
	TEST_ACCUMULATE(ok, tcp_simultaneous_close_scenario(),
			"simultaneous close failed: expected FIN-WAIT-1 -> CLOSING -> TIME-WAIT");
	TEST_ACCUMULATE(ok, tcp_sequence_wraparound_scenario(),
			"sequence wraparound failed: expected RCV.NXT=2 after 4 bytes at UINT32_MAX-1");
	TEST_ACCUMULATE(ok, tcp_out_of_order_reassembly_scenario(),
			"out-of-order reassembly failed: expected two 2-byte chunks and RCV.NXT=4");
	TEST_ACCUMULATE(ok, tcp_zero_window_update_scenario(),
			"window update failed: expected peer window 0 followed by 4096");
	/* Congestion control is reported by MUST-19 and SACK generation by
	 * ROBUST-12; they are not repeated here. */
	return ok;
}

static enum result test_tcp_state_transition_coverage(const char **why)
{
	pid_t child;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(tcp_state_transition_coverage_scenario() ? 0 : 1);
	if (!wait_test_child(child, 6000)) {
		*why = "extended TCP state transition coverage failed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_retransmitted_syn_ack_in_established(const char **why)
{
	const uint32_t peer_isn = 100;
	struct fixture f;
	struct tcp_packet_spec spec;
	void *ack;

	if (!fixture_init(&f)) {
		*why = "fixture initialization failed";
		return RESULT_FAIL;
	}

	/*
	 * Model an active OPEN whose final ACK was lost.  The peer retransmits
	 * its SYN+ACK after this endpoint has already entered ESTABLISHED.
	 */
	f.conn->seq_next_expected = peer_isn + 1;
	f.conn->ack_seq = peer_isn + 1;
	f.conn->ack_seq_xmitted = peer_isn + 1;
	fixture_incoming_spec(&f, &spec, peer_isn, NULL, 0);
	spec.ack_seq = f.conn->iss + 1;
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));

	if (f.conn->state != II_TCP_STATE_ESTABLISHED) {
		*why = "retransmitted SYN+ACK changed the ESTABLISHED state";
		return RESULT_FAIL;
	}
	if (f.conn->seq_next_expected != peer_isn + 1) {
		*why = "retransmitted SYN+ACK consumed the SYN sequence twice";
		return RESULT_FAIL;
	}
	if (output_count_ethertype(&f.state, 0x0800) != 1) {
		*why = "retransmitted SYN+ACK did not produce exactly one response";
		return RESULT_FAIL;
	}
	ack = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!ack || !PB_TCP_HDR_HAS_ACK(ack) || PB_TCP_HDR_HAS_SYN(ack) ||
			PB_TCP_HDR_HAS_FIN(ack) || PB_TCP_HDR_HAS_RST(ack) ||
			ii_ntohl(PB_TCP(ack)->ack_seq_be) != peer_isn + 1) {
		*why = "retransmitted SYN+ACK response was not the expected ACK";
		return RESULT_FAIL;
	}

	free_output(&f.state);
	return RESULT_PASS;
}

/*
 * MUST-10 (RFC 9293 Section 3.5, Figure 8): both ends send SYN.  After the
 * peer's SYN arrives in SYN-SENT, the local end enters SYN-RECEIVED and sends
 * SYN,ACK with its original ISS and ACK = peer ISS + 1; the peer's SYN,ACK
 * acknowledging the local SYN then establishes the connection.
 */
static enum result test_simultaneous_open(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *syn, *syn_ack = NULL;
	uint32_t local_iss;
	unsigned int i;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	f.conn->state = II_TCP_STATE_SYN_SENT;
	test_event_tcp_state_set(&f.state, f.conn, f.conn->state);
	test_api_push(f.ws, f.conn, NULL, 1, 0, 0, 0, 0, NULL, 0, &f.state);
	fixture_run_timers(&f);
	syn = output_nth_ethertype(&f.state, 0x0800, 0);
	if (!syn || !PB_TCP_HDR_HAS_SYN(syn) || PB_TCP_HDR_HAS_ACK(syn))
		return RESULT_FAIL;
	local_iss = ii_ntohl(PB_TCP(syn)->seq_be);
	free_output(&f.state);
	test_event_log_clear(&f.state);

	/* The peer's SYN crosses ours. */
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	if (!test_event_has_state_transition(&f.state, f.conn,
			II_TCP_STATE_SYN_SENT, II_TCP_STATE_SYN_RECVD)) {
		*why = "simultaneous open did not enter SYN-RECEIVED";
		return RESULT_FAIL;
	}
	for (i = 0; i < f.state.out_cnt; i++) {
		void *pkt = f.state.out[i];
		if (PB_IP4(pkt)->proto == 6 && PB_TCP_HDR_HAS_SYN(pkt) &&
				PB_TCP_HDR_HAS_ACK(pkt))
			syn_ack = pkt;
	}
	if (!syn_ack || ii_ntohl(PB_TCP(syn_ack)->seq_be) != local_iss ||
			ii_ntohl(PB_TCP(syn_ack)->ack_seq_be) != 101) {
		*why = "SYN-RECEIVED did not send SYN,ACK with the original ISS and ACK = peer ISS + 1";
		return RESULT_FAIL;
	}
	free_output(&f.state);

	/* The peer's SYN,ACK acknowledges our SYN. */
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	spec.ack_seq = local_iss + 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->state != II_TCP_STATE_ESTABLISHED) {
		*why = "simultaneous open did not reach ESTABLISHED";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int output_has_syn_ack(const struct test_state *state)
{
	unsigned int i;
	for (i = 0; i < state->out_cnt; i++) {
		void *pkt = state->out[i];
		if (PB_TCP_HDR_HAS_SYN(pkt) && PB_TCP_HDR_HAS_ACK(pkt) &&
				!PB_TCP_HDR_HAS_RST(pkt))
			return 1;
	}
	return 0;
}

static struct ii_tcp_conn *fixture_find_peer_port(struct fixture *f,
		uint16_t peer_port_be)
{
	for (uint32_t i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
		struct ii_tcp_conn *conn = &f->ws->tcp_conns.array[i];
		if (conn->state != II_TCP_STATE_CLOSED && ii_htons(conn->dst_port) == peer_port_be)
			return conn;
	}
	return NULL;
}

static enum result test_default_send_mss(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *default_conn;
	struct ii_tcp_conn *advertised_conn;
	struct ii_pb *p;
	const uint16_t default_port_be = ii_htons(21001);
	const uint16_t advertised_port_be = ii_htons(21002);
	uint16_t tcp_option_len;
	uint16_t expected_first_payload;
	void *payload;
	uint16_t lengths[2] = { 0, 0 };
	uint16_t total = 0;
	unsigned int count = 0;
	(void)why;

	if (!fixture_init(&f))
		return RESULT_FAIL;

	/* No MSS option: an IPv4 connection must retain the default Send-MSS. */
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.src_port_be = default_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	default_conn = fixture_find_peer_port(&f, default_port_be);
	if (!default_conn || default_conn->mss != 536)
		return RESULT_FAIL;
	/* Account for timestamps only when enabled on this connection. */
	tcp_option_len = II_CONF_TCP_OPT_TS_OK &&
		(default_conn->flags & II_TCP_CONN_FLAGS_OPT_SET_TS) ? 12 : 0;
	expected_first_payload = 536 - tcp_option_len;

	/* An MSS option must override the default, proving absence is detected. */
	fixture_incoming_spec(&f, &spec, 200, NULL, 0);
	spec.src_port_be = advertised_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	tcp_packet_add_mss(&spec, 1200);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	advertised_conn = fixture_find_peer_port(&f, advertised_port_be);
	if (!advertised_conn || advertised_conn->mss != 1200)
		return RESULT_FAIL;

	/* Verify that the default affects real segmentation, including options. */
	default_conn->state = II_TCP_STATE_ESTABLISHED;
	payload = iip_ops_pkt_alloc(&f.state);
	memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, 600);
	iip_ops_pkt_set_len(payload, 600, &f.state);
	test_api_push(f.ws, default_conn, payload, 0, 1, 0, 0, 0,
			NULL, 0, &f.state);
	free_output(&f.state);
	p = test_ring_end(f.ws, &default_conn->tx_ring, 1);
	if (ii_tcp_xmit_queued_data_one(f.ws, test_conn_id(f.ws, default_conn),
			(uint32_t)(p - f.ws->pbs.array), 0, p->tcp.payload_len, &f.state) != IIP_ERR_OK)
		return RESULT_FAIL;
	for (unsigned int i = 0; i < f.state.out_cnt; i++) {
		uint16_t len = PB_TCP_PAYLOAD_LEN(f.state.out[i]);
		if (count < 2) lengths[count] = len;
		count++;
		total = (uint16_t)(total + len);
	}
	return count == 2 && total == 600 &&
		lengths[0] == expected_first_payload &&
		lengths[1] == 600 - expected_first_payload
		? RESULT_PASS : RESULT_FAIL;
}

static int effective_send_mss_scenario(uint16_t send_mss,
		uint16_t path_mtu, uint16_t expected_first_payload)
{
	struct fixture f;
	struct ii_pb *p;
	void *payload;
	uint32_t expected_seq;
	uint16_t total_payload = expected_first_payload + 100;
	uint16_t lengths[2] = { 0, 0 };
	uint16_t total = 0;
	unsigned int count = 0;

	if (!fixture_init(&f))
		return 0;
	if (II_CONF_TCP_OPT_TS_OK) f.conn->flags |= II_TCP_CONN_FLAGS_OPT_SET_TS;
	f.conn->mss = send_mss;
	f.conn->path_mtu = path_mtu;
	expected_seq = f.conn->seq;
	payload = iip_ops_pkt_alloc(&f.state);
	memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, total_payload);
	iip_ops_pkt_set_len(payload, total_payload, &f.state);
	test_api_push(f.ws, f.conn, payload, 0, 1, 0, 0, 0,
			NULL, 0, &f.state);

	p = test_ring_end(f.ws, &f.conn->tx_ring, 0);
	if (ii_tcp_xmit_queued_data_one(f.ws, test_conn_id(f.ws, f.conn),
			(uint32_t)(p - f.ws->pbs.array), 0, p->tcp.payload_len, &f.state) != IIP_ERR_OK)
		return 0;
	for (unsigned int i = 0; i < f.state.out_cnt; i++) {
		uint16_t payload_len = PB_TCP_PAYLOAD_LEN(f.state.out[i]);
		if (count < 2)
			lengths[count] = payload_len;
		if (ii_ntohs(PB_IP4(f.state.out[i])->len_be) > path_mtu ||
				ii_ntohl(PB_TCP(f.state.out[i])->seq_be) != expected_seq ||
				!ip4_checksum_valid(f.state.out[i]) || !checksum_valid(f.state.out[i])) {
			fprintf(stderr, "effective MSS: send_mss=%u path_mtu=%u ip_len=%u payload=%u\n",
					send_mss, path_mtu,
					ii_ntohs(PB_IP4(f.state.out[i])->len_be), payload_len);
			return 0;
		}
		expected_seq += payload_len;
		total = (uint16_t)(total + payload_len);
		count++;
	}
	if (count != 2 || total != total_payload ||
			lengths[0] != expected_first_payload ||
			lengths[1] != total_payload - expected_first_payload) {
		fprintf(stderr, "effective MSS: send_mss=%u path_mtu=%u expected=%u/%u actual=%u/%u count=%u total=%u\n",
				send_mss, path_mtu, expected_first_payload,
				total_payload - expected_first_payload,
				lengths[0], lengths[1], count, total);
		return 0;
	}
	return 1;
}

static enum result test_effective_send_mss(const char **why)
{
	const uint16_t tcp_option_len = II_CONF_TCP_OPT_TS_OK ? 12 : 0;
	(void)why;
	/* Send-MSS is the limiting value. */
	if (!effective_send_mss_scenario(300, 1500,
			(uint16_t)(300 - tcp_option_len)))
		return RESULT_FAIL;
	/* The IP-layer MTU is the limiting value, including both fixed headers. */
	if (!effective_send_mss_scenario(1000, 600,
			(uint16_t)(600 - sizeof(struct iip_ip4_hdr) -
				sizeof(struct iip_tcp_hdr) - tcp_option_len)))
		return RESULT_FAIL;
	/* Close limits: the path MTU is slightly smaller than the Send-MSS. */
	if (!effective_send_mss_scenario(300, 330,
			(uint16_t)(330 - sizeof(struct iip_ip4_hdr) -
				sizeof(struct iip_tcp_hdr) - tcp_option_len)))
		return RESULT_FAIL;
	return RESULT_PASS;
}

static int syn_received_passive_origin_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *passive;
	const uint16_t peer_port_be = ii_htons(21000);
	uint32_t rst_seq;
	if (!fixture_init(&f))
		return 0;

	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	passive = fixture_find_peer_port(&f, peer_port_be);
	if (!passive || passive == f.conn ||
			passive->state != II_TCP_STATE_SYN_RECVD ||
			(passive->flags & II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN) ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_ACCEPT) != 1 ||
			!output_has_syn_ack(&f.state))
		return 0;
	rst_seq = ii_ntohl(ii_htonl(passive->ack_seq));
	free_output(&f.state);
	test_event_log_clear(&f.state);

	fixture_incoming_spec(&f, &spec, rst_seq, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_RST;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	/* RFC 9293 Section 3.10.7.4: the user need not be informed; doing so
	 * is not prohibited, so only the return to LISTEN is checked below. */

	/* Returning to the implicit LISTEN state must permit another SYN. */
	fixture_incoming_spec(&f, &spec, 200, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPT) != 1 || !output_has_syn_ack(&f.state))
		return 0;
	free_output(&f.state);
	return 1;
}

static int syn_received_active_origin_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	uint32_t rst_seq;
	if (!fixture_init(&f))
		return 0;
	f.conn->state = II_TCP_STATE_SYN_SENT;
	test_event_tcp_state_set(&f.state, f.conn, f.conn->state);
	test_event_log_clear(&f.state);

	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->state != II_TCP_STATE_SYN_RECVD ||
			!(f.conn->flags & II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN) ||
			!test_event_has_state_transition(&f.state, f.conn,
					II_TCP_STATE_SYN_SENT,
					II_TCP_STATE_SYN_RECVD))
		return 0;
	rst_seq = f.conn->ack_seq;
	free_output(&f.state);
	test_event_log_clear(&f.state);

	fixture_incoming_spec(&f, &spec, rst_seq, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_RST;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return test_event_has_state_transition(&f.state, f.conn,
			II_TCP_STATE_SYN_RECVD, II_TCP_STATE_CLOSED) &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1;
}

static int pre_established_syn_rst_scenario(void)
{
	struct fixture closed, listen, syn_sent_no_ack, syn_sent_ack;
	struct tcp_packet_spec spec;
	const uint16_t listen_peer_port_be = ii_htons(21001);

	/* CLOSED and LISTEN ignore an incoming RST, even when SYN is also set. */
	if (!fixture_init(&closed))
		return 0;
	closed.conn->state = II_TCP_STATE_CLOSED;
	fixture_incoming_spec(&closed, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_RST;
	fixture_deliver(&closed, build_tcp_packet(&spec, &closed.state));
	TEST_CONDITION(closed.conn->state == II_TCP_STATE_CLOSED,
			"CLOSED + SYN|RST changed state: expected=CLOSED actual=%u",
			closed.conn->state);
	TEST_CONDITION(closed.state.out_cnt == 0,
			"CLOSED + SYN|RST generated %u response packet(s); expected none",
			closed.state.out_cnt);
	TEST_CONDITION(test_event_count(&closed.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_ACCEPT) == 0,
			"CLOSED + SYN|RST invoked the accept callback");

	if (!fixture_init(&listen) ||
			!test_tcp_listen(&listen.state, ii_htonl(listen.conn->src_ip[0]),
				ii_htons(listen.conn->src_port), ii_htonl(listen.conn->dst_ip[0]),
				listen_peer_port_be, NULL))
		return 0;
	fixture_incoming_spec(&listen, &spec, 0, NULL, 0);
	spec.src_port_be = listen_peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_RST;
	fixture_deliver(&listen, build_tcp_packet(&spec, &listen.state));
	TEST_CONDITION(listen.state.out_cnt == 0,
			"LISTEN + SYN|RST generated %u response packet(s); expected none",
			listen.state.out_cnt);
	TEST_CONDITION(test_event_count(&listen.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_ACCEPT) == 0,
			"LISTEN + SYN|RST invoked the accept callback");
	TEST_CONDITION(fixture_find_peer_port(&listen,
				listen_peer_port_be) == NULL,
			"LISTEN + SYN|RST created a child connection for peer port %u",
			ii_ntohs(listen_peer_port_be));

	/*
	 * In SYN-SENT, RST is effective only when its ACK is acceptable.
	 * Without ACK the segment is silently dropped.
	 */
	if (!fixture_init(&syn_sent_no_ack))
		return 0;
	syn_sent_no_ack.conn->state = II_TCP_STATE_SYN_SENT;
	test_event_tcp_state_set(&syn_sent_no_ack.state, syn_sent_no_ack.conn,
			syn_sent_no_ack.conn->state);
	test_event_log_clear(&syn_sent_no_ack.state);
	fixture_incoming_spec(&syn_sent_no_ack, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_RST;
	fixture_deliver(&syn_sent_no_ack,
			build_tcp_packet(&spec, &syn_sent_no_ack.state));
	TEST_CONDITION(syn_sent_no_ack.conn->state == II_TCP_STATE_SYN_SENT,
			"SYN-SENT + SYN|RST without ACK changed state: expected=SYN-SENT actual=%u",
			syn_sent_no_ack.conn->state);
	TEST_CONDITION(syn_sent_no_ack.state.out_cnt == 0,
			"SYN-SENT + SYN|RST without ACK generated %u response packet(s)",
			syn_sent_no_ack.state.out_cnt);
	TEST_CONDITION(test_event_count(&syn_sent_no_ack.state,
				TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 0,
			"SYN-SENT + SYN|RST without ACK invoked the closed callback");

	if (!fixture_init(&syn_sent_ack))
		return 0;
	fixture_prepare_sender(&syn_sent_ack);
	syn_sent_ack.conn->state = II_TCP_STATE_SYN_SENT;
	test_api_push(syn_sent_ack.ws, syn_sent_ack.conn, NULL,
			1, 0, 0, 0, 0, NULL, 0, &syn_sent_ack.state);
	fixture_run_timers(&syn_sent_ack);
	TEST_CONDITION(syn_sent_ack.state.out_cnt &&
			PB_TCP_HDR_HAS_SYN(syn_sent_ack.state.out[0]),
			"SYN-SENT RST control: no transmitted SYN");
	free_output(&syn_sent_ack.state);
	test_event_tcp_state_set(&syn_sent_ack.state, syn_sent_ack.conn,
			syn_sent_ack.conn->state);
	test_event_log_clear(&syn_sent_ack.state);
	fixture_incoming_spec(&syn_sent_ack, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_RST | TEST_TCP_ACK;
	fixture_deliver(&syn_sent_ack,
			build_tcp_packet(&spec, &syn_sent_ack.state));
	TEST_CONDITION(test_event_has_state_transition(&syn_sent_ack.state,
				syn_sent_ack.conn, II_TCP_STATE_SYN_SENT,
				II_TCP_STATE_CLOSED),
			"SYN-SENT + SYN|RST with acceptable ACK did not transition to CLOSED");
	TEST_CONDITION(test_event_count(&syn_sent_ack.state,
				TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 1,
			"SYN-SENT + SYN|RST with acceptable ACK produced %u closed callback(s); expected 1",
			test_event_count(&syn_sent_ack.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED));
	return 1;
}

static enum result test_syn_received_origin(const char **why)
{
	pid_t child;
	int passive_ok;
	int active_ok;
	int pre_established_ok;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child) {
		pre_established_ok = pre_established_syn_rst_scenario();
		passive_ok = syn_received_passive_origin_scenario();
		active_ok = syn_received_active_origin_scenario();
		_exit(pre_established_ok && passive_ok && active_ok ? 0 : 1);
	}
	if (!wait_test_child(child, 2000)) {
		*why = "SYN|RST handling before ESTABLISHED or SYN-RECEIVED origin handling failed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_passive_open_isolation(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct test_listener *listener_a, *listener_b;
	struct test_listener listener_a_before;
	const struct test_event *accept_event;
	unsigned int i;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	listener_a = test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(10000), 0, 0, (void *)(uintptr_t)1);
	if (!listener_a)
		return RESULT_FAIL;
	listener_a_before = *listener_a;
	listener_b = test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(10001), 0, 0, (void *)(uintptr_t)2);
	if (!listener_b || listener_b == listener_a ||
			memcmp(listener_a, &listener_a_before,
				sizeof(*listener_a)) != 0) {
		*why = "a passive OPEN modified a previously created listener";
		return RESULT_FAIL;
	}

	/* Exhaust the application listener table.  The failing passive OPEN
	 * must leave every previously created record untouched. */
	for (i = 2; i < TEST_LISTENER_MAX; i++)
		if (!test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
				ii_htons((uint16_t)(10000 + i)), 0, 0,
				(void *)(uintptr_t)(i + 1)))
			return RESULT_FAIL;
	if (test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			ii_htons(11000), 0, 0, NULL) ||
			f.state.listener_count != TEST_LISTENER_MAX ||
			memcmp(listener_a, &listener_a_before,
				sizeof(*listener_a)) != 0) {
		*why = "a failed passive OPEN affected an existing listener";
		return RESULT_FAIL;
	}

	/* A SYN accepted through listener A creates a child connection while
	 * both A and B remain independent, usable listener records. */
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.src_port_be = ii_htons(21001);
	spec.dst_port_be = listener_a->local_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	accept_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPT, 0);
	if (!accept_event || accept_event->value[0] != 1 ||
			!output_has_syn_ack(&f.state) ||
			memcmp(listener_a, &listener_a_before,
				sizeof(*listener_a)) != 0 || !listener_b->active) {
		*why = "accepting on one passive OPEN affected another listener";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	test_event_log_clear(&f.state);

	fixture_incoming_spec(&f, &spec, 200, NULL, 0);
	spec.src_port_be = ii_htons(21002);
	spec.dst_port_be = listener_b->local_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	accept_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPT, 0);
	if (!accept_event || accept_event->value[0] != 2 ||
			!output_has_syn_ack(&f.state) ||
			memcmp(listener_a, &listener_a_before,
				sizeof(*listener_a)) != 0) {
		*why = "independent passive OPEN records did not remain usable";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}


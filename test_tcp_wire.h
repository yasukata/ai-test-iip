/* Receive ordering, destination filtering, and TCP wire fields/options.
 * Included in dependency order by test_tcp.h.
 */

static int broadcast_multicast_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.dst_ip_be = ii_htonl(0xe0000001U);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.tcp_input_filter_rejected != 1 ||
			f.state.payload_chunk_count || f.state.out_cnt ||
			f.conn->seq_next_expected != 0)
		return 0;
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.dst_ip_be = ii_htonl(0xffffffffU);
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.tcp_input_filter_rejected != 2 ||
			f.state.payload_chunk_count || f.state.out_cnt ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_ACCEPTED))
		return 0;
	/* An always-discard filter must not pass the requirement test. */
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	int ok = f.state.tcp_input_filter_rejected == 2 &&
		f.state.payload_chunk_count == 1 &&
		f.state.payload_byte_count == 1 &&
		f.conn->seq_next_expected == 1 && f.state.out_cnt != 0;
	ii_tcp_conn_enter_close_phase(f.ws, test_conn_id(f.ws, f.conn));
	if (ii_tcp_conn_close_check(f.ws, test_conn_id(f.ws, f.conn),
			&f.state) != IIP_ERR_OK)
		ok = 0;
	free_output(&f.state);
	free(f.ws);
	return ok;
}

static enum result test_broadcast_multicast_discard(const char **why)
{
	pid_t child;
	(void)why;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(broadcast_multicast_scenario() ? 0 : 1);
	return wait_test_child(child, 1000) ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ack_aggregation(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0, 1 };
	void *input[2];
	uint32_t next_us = UINT32_MAX;
	unsigned int i, round, acks = 0;
	int full_ack = 0;
	if (!fixture_init(&f)) return RESULT_FAIL;
	f.state.defer_payload_consumption = 1;
	fixture_incoming_spec(&f, &spec, 0, &payload[0], 1);
	input[0] = build_tcp_packet(&spec, &f.state);
	fixture_incoming_spec(&f, &spec, 1, &payload[1], 1);
	input[1] = build_tcp_packet(&spec, &f.state);
	assert(test_api_run(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]),
			input, 2, &next_us, &f.state) == 2);
	for (round = 0; round < 2; round++) {
		if (round) {
			free_output(&f.state);
			fixture_advance_ms(&f, 499);
		}
		for (i = 0; i < f.state.out_cnt; i++) {
			void *pkt = f.state.out[i];
			if (ii_ntohs(iip_ops_l2_ethertype_be(pkt, &f.state)) != 0x0800 ||
					PB_IP4(pkt)->proto != 6 || !PB_TCP_HDR_HAS_ACK(pkt)) continue;
			acks++;
			if (!checksum_valid(pkt)) {
				*why = "aggregated ACK has an invalid checksum";
				return RESULT_FAIL;
			}
			if (ii_ntohl(PB_TCP(pkt)->ack_seq_be) == 2) full_ack = 1;
		}
	}
	if (f.state.payload_byte_count != 2 || !full_ack || acks != 1) {
		*why = "queued input did not produce exactly one valid cumulative ACK before 500 ms";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * MUST-59: when a segment fills a hole, all queued out-of-order data that
 * becomes contiguous must be processed before the ACK is sent, so every
 * ACK emitted after the filling segment acknowledges the whole contiguous
 * range.  (SACK block ordering, RFC 2018, is a separate concern covered by
 * the legacy SACK regression test.)
 */
static enum result test_ooo_before_ack(const char **why)
{
	static const uint8_t payload[3] = { 0, 1, 2 };
	struct fixture f;
	struct tcp_packet_spec spec;
	unsigned int i, round;
	int full_ack = 0;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	/* Queue [1, 3) while [0, 1) is missing. */
	fixture_incoming_spec(&f, &spec, 1, &payload[1], 2);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.payload_byte_count != 0) {
		*why = "out-of-order data was delivered before the hole was filled";
		return RESULT_FAIL;
	}
	free_output(&f.state);

	/*
	 * Fill the hole.  An ACK that acknowledges the filling segment but not
	 * the queued data (0 < SEG.ACK < 3) shows that the ACK was generated
	 * before the queue was processed.  A duplicate ACK left over from the
	 * out-of-order arrival (SEG.ACK = 0) is not a response to the filling
	 * segment.  The cumulative ACK may be delayed, but by less than
	 * 0.5 seconds (MUST-40).
	 */
	fixture_incoming_spec(&f, &spec, 0, &payload[0], 1);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	for (round = 0; round < 2 && !full_ack; round++) {
		if (round) {
			fixture_advance_ms(&f, 499);
		}
		for (i = 0; i < f.state.out_cnt; i++) {
			void *pkt = f.state.out[i];
			uint32_t ack;
			if (ii_ntohs(iip_ops_l2_ethertype_be(pkt, &f.state)) != 0x0800 ||
					PB_IP4(pkt)->proto != 6 || !PB_TCP_HDR_HAS_ACK(pkt))
				continue;
			ack = ii_ntohl(PB_TCP(pkt)->ack_seq_be);
			if (ack > 0 && ack < sizeof(payload)) {
				*why = "an ACK was sent before queued out-of-order data was processed";
				return RESULT_FAIL;
			}
			if (ack == sizeof(payload))
				full_ack = 1;
		}
		free_output(&f.state);
	}
	if (!full_ack || f.state.payload_byte_count != sizeof(payload)) {
		*why = "filling the hole did not deliver and acknowledge the queued data";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int no_indefinite_buffering_scenario(void)
{
	struct fixture f;
	void *payload;
	unsigned int i;
	uint32_t next_us = UINT32_MAX;
	if (!fixture_init(&f))
		return 0;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	f.conn->peer_win = 65535;
	f.conn->acked_seq = f.conn->seq;
	f.conn->ack_seq_xmitted = f.conn->ack_seq;
	payload = iip_ops_pkt_alloc(&f.state);
	((uint8_t *)iip_ops_pkt_get_data(payload, &f.state))[0] = 0x5a;
	iip_ops_pkt_set_len(payload, 1, &f.state);
	test_api_send(f.ws, f.conn, payload, 0, &f.state);
	assert(test_api_run(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]),
			NULL, 0, &next_us, &f.state) == 0);
	for (unsigned ms = 0; ms <= 10000; ms += 10) {
	for (i = 0; i < f.state.out_cnt; i++) {
		if (PB_TCP_PAYLOAD_LEN(f.state.out[i]) == 1)
			return 1;
	}
	free_output(&f.state);
	fixture_advance_ms(&f, 10);
	}
	return 0;
}

static enum result test_no_indefinite_buffering(const char **why)
{
    if (no_indefinite_buffering_scenario()) return RESULT_PASS;
    *why = "no transmission within 10s observation budget; indefinite buffering not proven";
    return RESULT_INCONCLUSIVE;
}

static int invalid_source_syn_scenario(void)
{
	static const uint32_t invalid_sources[] = {
		0x00000000U, 0x00ffffffU,
		0xe0000000U, 0xefffffffU,
		0xf0000000U, 0xffffffffU,
	};
	unsigned int i;
	for (i = 0; i < sizeof(invalid_sources) / sizeof(invalid_sources[0]); i++) {
		struct fixture f;
		struct tcp_packet_spec spec;
		if (!fixture_init(&f))
			return 0;
		fixture_incoming_spec(&f, &spec, 100, NULL, 0);
		spec.src_ip_be = ii_htonl(invalid_sources[i]);
		spec.src_port_be = ii_htons(30000 + i);
		spec.tcp_flags = TEST_TCP_SYN;
		fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
		if (f.state.out_cnt != 0)
			return 0;
	}
	{
		struct fixture f;
		struct tcp_packet_spec spec;
		if (!fixture_init(&f))
			return 0;
		fixture_incoming_spec(&f, &spec, 100, NULL, 0);
		spec.src_ip_be = ii_htonl(0x01000001U); /* valid boundary above 0/8 */
		spec.src_port_be = ii_htons(31000);
		spec.tcp_flags = TEST_TCP_SYN;
		fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
		if (f.state.out_cnt == 0)
			return 0;
	}
	return 1;
}

static enum result test_invalid_source_syn(const char **why)
{
	pid_t child;
	(void)why;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(invalid_source_syn_scenario() ? 0 : 1);
	return wait_test_child(child, 1000) ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_unaligned_options(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t timestamp[] = { 0, 0, 0, 1, 0, 0, 0, 0 };
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	tcp_packet_add_nop(&spec);
	tcp_packet_add_option(&spec, 8, timestamp, sizeof(timestamp));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.conn->state == II_TCP_STATE_ESTABLISHED
		? RESULT_PASS : RESULT_FAIL;
}

static enum result test_window_unsigned(const char **why)
{
	uint16_t window = ii_ntohs(test_compute_tcp_window(65535, 0));
	TEST_REQUIRE(why, window == 65535,
		"TCP window: expected=65535, actual=%u", (unsigned)window);
	return RESULT_PASS;
}

static enum result test_tx_checksum(const char **why)
{
	struct fixture f;
	void *pkt;
	int valid;
	(void)why;
	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 0, 0, 7)))
		return RESULT_FAIL;
	valid = checksum_valid(pkt);
	iip_ops_pkt_free(pkt, &f.state);
	TEST_REQUIRE(why, valid, "TCP output checksum: expected valid=1, actual=%d", valid);
	return RESULT_PASS;
}

/*
 * MUST-14 and MUST-67: a SYN carries an MSS option, and the value must not
 * exceed MMS_R - 20 (RFC 9293 Section 3.7.1), so a segment carrying that many
 * data octets must be receivable.  Check the option format, bound the value,
 * and deliver a segment of exactly the advertised size instead of comparing
 * it with the implementation's configured initial MSS.
 */
static enum result test_syn_options(const char **why)
{
	static uint8_t data[2048];
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;
	uint8_t *mss;
	uint16_t advertised = 0;
	int has_mss = 0;

	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 1, 0, 0)))
		return RESULT_FAIL;
	mss = option_find(pkt, 2);
	if (mss && mss[1] == 4) {
		advertised = (uint16_t)(mss[2] << 8 | mss[3]);
		has_mss = 1;
	}
	iip_ops_pkt_free(pkt, &f.state);
	if (!has_mss) {
		*why = "no MSS option in this SYN; sending capability not established by this sample";
		return RESULT_INCONCLUSIVE;
	}
	if (advertised == 0 || advertised > 65535U - 40U) {
		*why = "advertised MSS is outside the possible range";
		return RESULT_FAIL;
	}
	if ((uint32_t)advertised + 14U + 20U + 20U > sizeof(data)) {
		*why = "advertised MSS exceeds a single test frame; receivability not checked";
		return RESULT_SKIP;
	}

	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.state.accept_arbitrary_payload = 1;
	f.state.quiet_payload = 1;
	fixture_incoming_spec(&f, &spec, 0, data, advertised);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.payload_byte_count != advertised) {
		*why = "a segment of the advertised MSS was not accepted";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_required_options(const char **why)
{
	/* A header ending at an option boundary needs no EOL. Also exercise
	 * NOP before an unaligned MSS, and EOL followed by zero padding. */
	for (unsigned int variant = 0; variant < 3; variant++) {
		struct fixture f;
		struct tcp_packet_spec spec;
		const uint8_t payload[] = { 0 };
		const uint8_t padding[] = { 0, 0 };
		int accepted;

		if (!fixture_init(&f)) {
			*why = "fixture initialization failed";
			return RESULT_FAIL;
		}
		f.conn->state = II_TCP_STATE_SYN_SENT;
		f.conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
		fixture_incoming_spec(&f, &spec, 100, NULL, 0);
		spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
		spec.ack_seq = f.conn->seq + 1;
		if (variant)
			tcp_packet_add_nop(&spec);
		/* The zero inside this MSS value is data, not an EOL kind. */
		tcp_packet_add_mss(&spec, 1024);
		if (variant == 1) {
			for (unsigned int i = 0; i < 3; i++)
				tcp_packet_add_nop(&spec);
		} else if (variant == 2) {
			tcp_packet_add_eol(&spec);
			tcp_packet_add_raw_option(&spec, padding, sizeof(padding));
		}
		fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
		accepted = f.conn->state == II_TCP_STATE_ESTABLISHED &&
			f.conn->mss == 1024 && f.conn->seq_next_expected == 101;
		if (accepted) {
			/* Valid options must not prevent subsequent data delivery. */
			fixture_incoming_spec(&f, &spec, 101, payload, sizeof(payload));
			fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
			accepted = f.state.payload_chunk_count == 1 &&
				f.state.payload_byte_count == sizeof(payload) &&
				f.conn->seq_next_expected == 102;
		}
		ii_tcp_conn_enter_close_phase(f.ws, test_conn_id(f.ws, f.conn));
		if (ii_tcp_conn_close_check(f.ws, test_conn_id(f.ws, f.conn),
				&f.state) != IIP_ERR_OK)
			accepted = 0;
		free_output(&f.state);
		free(f.ws);
		if (!accepted) {
			*why = variant == 0 ? "MSS without EOL was not accepted" :
				variant == 1 ? "NOP and unaligned MSS were not accepted" :
				"EOL with zero padding prevented MSS negotiation or data delivery";
			return RESULT_FAIL;
		}
	}
	return test_syn_options(why);
}

static enum result test_ttl(const char **why)
{
	struct fixture f;
	void *pkt;
	int ok;
	(void)why;
	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 0, 0, 0)))
		return RESULT_FAIL;
	ok = PB_IP4(pkt)->ttl == TEST_IP4_TTL;
	iip_ops_pkt_free(pkt, &f.state);
	return ok ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_diffserv(const char **why)
{
	struct fixture f;
	void *pkt;
	void *opaque = &f.state;
	uint32_t initial_rto;
	const uint8_t diffserv = 0xb8; /* DSCP EF (46), ECN Not-ECT. */
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;

	/* The default DS field remains zero. */
	pkt = fixture_packet(&f, 0, 0, 0);
	if (!pkt || PB_IP4(pkt)->tos != 0 || !ip4_checksum_valid(pkt)) {
		if (pkt)
			iip_ops_pkt_free(pkt, opaque);
		return RESULT_FAIL;
	}
	iip_ops_pkt_free(pkt, opaque);

	/* An application-selected value is applied to data and retransmission. */
	fixture_prepare_sender(&f);
	test_set_diffserv(f.ws, f.conn, diffserv, &f.state);
	if (!fixture_send_data(&f, 1) || f.state.out_cnt != 1 ||
			PB_IP4(f.state.out[0])->tos != diffserv ||
			!ip4_checksum_valid(f.state.out[0]))
		return RESULT_FAIL;
	initial_rto = f.conn->rto_ms;
	free_output(&f.state);
	test_event_log_clear(&f.state);
	fixture_advance_ms(&f, (uint64_t)initial_rto + 1);
	return test_event_count(&f.state, TEST_EVENT_RETRANSMISSION,
			TEST_RETRANS_TIMEOUT) == 1 && f.state.out_cnt == 1 &&
		PB_IP4(f.state.out[0])->tos == diffserv &&
		ip4_checksum_valid(f.state.out[0]) ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_psh_last(const char **why)
{
	struct fixture f;
	void *pkt;
	int ok;
	(void)why;
	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 0, 0, 1)))
		return RESULT_FAIL;
	ok = PB_TCP_HDR_HAS_PSH(pkt);
	iip_ops_pkt_free(pkt, &f.state);
	return ok ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_mss_syn_only(const char **why)
{
	struct fixture f;
	void *pkt;
	int ok;
	(void)why;
	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 0, 0, 0)))
		return RESULT_FAIL;
	ok = option_find(pkt, 2) == NULL;
	iip_ops_pkt_free(pkt, &f.state);
	return ok ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_option_lengths(const char **why)
{
	struct fixture f;
	void *pkt;
	uint8_t *o;
	uint16_t at, n;
	(void)why;
	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 1, 0, 0)))
		return RESULT_FAIL;
	o = PB_TCP_OPT(pkt); n = PB_TCP_OPTLEN(pkt);
	for (at = 0; at < n && o[at] != 0; ) {
		if (o[at] == 1) { at++; continue; }
		if (at + 2 > n || o[at + 1] < 2 || at + o[at + 1] > n) {
			iip_ops_pkt_free(pkt, &f.state);
			return RESULT_FAIL;
		}
		at += o[at + 1];
	}
	iip_ops_pkt_free(pkt, &f.state);
	return RESULT_PASS;
}

static enum result test_zero_padding(const char **why)
{
	struct fixture f;
	void *pkt;
	uint8_t *o;
	uint16_t at, n;
	(void)why;
	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 1, 0, 0)))
		return RESULT_FAIL;
	o = PB_TCP_OPT(pkt); n = PB_TCP_OPTLEN(pkt);
	for (at = 0; at < n && o[at]; )
		at += o[at] == 1 ? 1 : o[at + 1];
	for (; at < n; at++)
		if (o[at] != 0) {
			iip_ops_pkt_free(pkt, &f.state);
			return RESULT_FAIL;
		}
	iip_ops_pkt_free(pkt, &f.state);
	return RESULT_PASS;
}


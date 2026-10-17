/* Delayed ACK, zero-window probing, and sender/receiver SWS avoidance.
 * Included in dependency order by test_tcp.h.
 */

/*
 * MUST-40: an ACK may be delayed, but by less than 0.5 seconds (RFC 9293
 * Section 3.8.6.3).  Accept an immediate ACK or one emitted by the timers at
 * any point before 500 ms have elapsed.
 */
static enum result test_delayed_ack_limit(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	unsigned int elapsed, i;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	for (elapsed = 0; elapsed < 500; elapsed++) {
		for (i = 0; i < f.state.out_cnt; i++) {
			void *pkt = f.state.out[i];
			if (PB_IP4(pkt)->proto == 6 && PB_TCP_HDR_HAS_ACK(pkt) &&
					ii_ntohl(PB_TCP(pkt)->ack_seq_be) == sizeof(payload))
				return RESULT_PASS;
		}
		free_output(&f.state);
		if (elapsed + 1 >= 500)
			break;
		fixture_advance_ms(&f, 1);
	}
	*why = "received data was not acknowledged within 0.5 seconds";
	return RESULT_FAIL;
}

static enum result test_window_shrink_robustness(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_pb *unacked;
	void *retransmission;
	uint32_t initial_rto, snd_una;
	uint16_t expected_packet_len;
	void *opaque = &f.state;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	snd_una = f.conn->acked_seq;
	if (!fixture_send_data(&f, 2))
		return RESULT_FAIL;
	unacked = test_ring_end(f.ws, &f.conn->sent_ring, 0);
	if (!unacked || unacked->tcp.payload_len != 2)
		return RESULT_FAIL;
	initial_rto = f.conn->rto_ms;
	if (!initial_rto)
		return RESULT_FAIL;
	free_output(&f.state);
	test_event_log_clear(&f.state);

	/* Keep SND.UNA unchanged, but move the advertised right edge behind
	 * SND.NXT.  This leaves one byte of the old segment in the new window
	 * and makes the usable window negative. */
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = snd_una;
	spec.window = 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->peer_win != 1 || test_ring_end(f.ws, &f.conn->sent_ring, 0) != unacked) {
		*why = "a shrinking window discarded the unacknowledged segment";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	test_event_log_clear(&f.state);

	fixture_advance_ms(&f, (uint64_t)initial_rto + 1);
	if (test_ring_end(f.ws, &f.conn->sent_ring, 0) != unacked ||
			test_event_count(&f.state, TEST_EVENT_RETRANSMISSION,
				TEST_RETRANS_TIMEOUT) != 1 || f.state.out_cnt != 1) {
		*why = "window shrink suppressed retransmission of old unacknowledged data";
		return RESULT_FAIL;
	}
	retransmission = f.state.out[0];
	expected_packet_len = iip_ops_l2_hdr_len(retransmission, opaque) +
			ii_ntohs(PB_IP4(retransmission)->len_be);
	if (iip_ops_pkt_get_len(retransmission, opaque) != expected_packet_len) {
		*why = "partial retransmission has an invalid packet length";
		return RESULT_FAIL;
	}
	if (!ip4_checksum_valid(retransmission) ||
			!checksum_valid(retransmission)) {
		*why = "partial retransmission has an invalid checksum";
		return RESULT_FAIL;
	}
	/*
	 * SHLD-16 asks for the old data inside the window to be retransmitted;
	 * MAY-7 also permits retransmitting old data beyond SND.UNA + SND.WND.
	 * Either one octet or the whole two-octet segment is therefore valid.
	 * PSH placement is not constrained here, and no FIN is queued.
	 */
	if (PB_TCP_PAYLOAD_LEN(retransmission) < 1 ||
			PB_TCP_PAYLOAD_LEN(retransmission) > 2 ||
			PB_TCP_HDR_HAS_FIN(retransmission)) {
		*why = "retransmission after window shrink has an invalid payload length or FIN";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_standard_window_probing(const char **why)
{
	struct fixture f;
	uint32_t at[3];

	if (!fixture_init(&f) || !fixture_queue_data_at_zero_window(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	if (fixture_wait_for_zero_window_probes(&f, 3, 600, at) != 3) {
		*why = "zero-window probes did not follow the retransmission procedure";
		return RESULT_FAIL;
	}
	if (at[1] - at[0] > at[2] - at[1]) {
		*why = "zero-window probe intervals backed off in the wrong direction";
		return RESULT_FAIL;
	}
	if (f.conn->state != II_TCP_STATE_ESTABLISHED) {
		*why = "window probing unexpectedly closed the connection";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int test_fin_only_at_zero_window(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	unsigned int i;
	int fin_seen = 0;

	/*
	 * A FIN with no data cannot carry the one data octet of a classic
	 * zero-window probe.  RFC 9293 requires that a zero window be probed
	 * (MUST-36) and that the connection survive a window that stays zero
	 * (MUST-37); it does not forbid sending the FIN itself while the
	 * window is zero.  Require only that the connection survive and that
	 * the FIN be delivered once the window reopens.
	 */
	if (!fixture_init(&f))
		return 0;
	fixture_prepare_sender(&f);
	f.conn->peer_win = 0;
	if (test_api_close(f.ws, f.conn, &f.state) == 0xffff)
		return 0;
	fixture_run_timers(&f);
	fake_clock_advance_sec(&f.state, 120);
	fixture_run_timers(&f);
	for (i = 0; i < f.state.out_cnt; i++)
		if (PB_TCP_HDR_HAS_FIN(f.state.out[i]) &&
				PB_TCP_PAYLOAD_LEN(f.state.out[i]) == 0)
			fin_seen = 1;
	if (f.conn->state != II_TCP_STATE_FIN_WAIT1) {
		*why = "connection did not stay in FIN-WAIT-1 while the window stayed zero";
		return 0;
	}
	free_output(&f.state);

	/* Reopen one sequence number without acknowledging the FIN. */
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	for (i = 0; i < f.state.out_cnt; i++) {
		void *pkt = f.state.out[i];
		if (PB_TCP_HDR_HAS_FIN(pkt) && PB_TCP_PAYLOAD_LEN(pkt) == 0) {
			if (!ip4_checksum_valid(pkt) || !checksum_valid(pkt)) {
				*why = "FIN-only segment has an invalid checksum";
				return 0;
			}
			fin_seen = 1;
		}
	}
	if (!fin_seen) {
		*why = "queued FIN-only was not sent after the window reopened";
		return 0;
	}
	return 1;
}

static enum result test_zero_window_probe(const char **why)
{
	struct fixture f;
	uint32_t at[1];

	if (!test_fin_only_at_zero_window(why))
		return RESULT_FAIL;
	if (!fixture_init(&f) || !fixture_queue_data_at_zero_window(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	if (fixture_wait_for_zero_window_probes(&f, 1, 120, at) != 1) {
		*why = "the sender did not probe a zero receive window";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * MUST-37: a sender must keep the connection open as long as the receiver
 * keeps acknowledging its zero-window probes, however long the window stays
 * closed.  Silence from the receiver is a different situation, so every probe
 * here is answered with an ACK that keeps the window at zero.
 */
static enum result test_indefinite_zero_window_connection(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	unsigned int second, i, probes = 0;

	if (!fixture_init(&f) || !fixture_queue_data_at_zero_window(&f))
		return RESULT_FAIL;
	/* Make accidental use of the normal retransmission failure threshold
	 * immediately visible while simulating one day of a closed window. */
	f.conn->retrans_r1 = 1;
	f.conn->retrans_r2 = 1;
	test_event_log_clear(&f.state);
	for (second = 0; second < 24U * 60U * 60U; second += 10) {
		int probed = 0;
		fake_clock_advance_sec(&f.state, 10);
		fixture_run_timers(&f);
		for (i = 0; i < f.state.out_cnt; i++) {
			void *pkt = f.state.out[i];
			if (PB_TCP_HDR_HAS_ACK(pkt) && PB_TCP_PAYLOAD_LEN(pkt) >= 1 &&
					!PB_TCP_HDR_HAS_SYN(pkt) &&
					!PB_TCP_HDR_HAS_RST(pkt))
				probed = 1;
		}
		free_output(&f.state);
		if (probed) {
			probes++;
			/* Acknowledge the probe without opening the window. */
			fixture_incoming_spec(&f, &spec, f.conn->ack_seq, NULL, 0);
			spec.ack_seq = f.conn->acked_seq;
			spec.window = 0;
			fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
			free_output(&f.state);
		}
		if (f.conn->state != II_TCP_STATE_ESTABLISHED ||
				test_event_count(&f.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_CLOSED) != 0) {
			*why = "a zero window with acknowledged probes caused connection termination";
			return RESULT_FAIL;
		}
		test_event_log_clear(&f.state);
	}
	if (!probes) {
		*why = "the sender never probed the zero window";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int test_sws_override_timeout(const char **why, uint16_t effective_mss)
{
	struct fixture f;
	unsigned int i;
	struct tcp_packet_spec spec;
	void *payload;
	void *opaque = &f.state;

	if (!fixture_init(&f))
		return 0;
	fixture_prepare_sender(&f);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = effective_mss;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	free_output(&f.state);
	test_event_log_clear(&f.state);

	payload = iip_ops_pkt_alloc(opaque);
	if (!payload)
		return 0;
	memset(iip_ops_pkt_get_data(payload, opaque), 0x5a, effective_mss);
	iip_ops_pkt_set_len(payload, effective_mss, opaque);
	if (test_api_send(f.ws, f.conn, payload, 0, opaque) == 0xffff)
		return 0;
	fixture_run_timers(&f);
	if (f.state.out_cnt || (f.conn->flags & II_TCP_CONN_FLAGS_SET_PROBE) ||
			!test_ring_end(f.ws, &f.conn->tx_ring, 0)) {
		*why = "SWS override timer did not start in the suppressed state";
		return 0;
	}

	/* The override timeout should be in the range 0.1 to 1.0 seconds
	 * (RFC 9293 Section 3.8.6.2.1); no particular value is required. */
	fixture_advance_ms(&f, 99);
	if (f.state.out_cnt || (f.conn->flags & II_TCP_CONN_FLAGS_SET_PROBE) ||
			!test_ring_end(f.ws, &f.conn->tx_ring, 0)) {
		*why = "SWS override sent data before 0.1 seconds";
		return 0;
	}
	for (i = 0; i < 10 && !f.state.out_cnt; i++) {
		fixture_advance_ms(&f, 100);
	}
	/* A normal transmission advances SND.NXT by the octet sent.  iip keeps
	 * a partially transmitted buffer in tx_ring until all of it has been
	 * sent, so sent_ring membership is not a usable oracle here. */
	if (f.state.out_cnt != 1 ||
			PB_TCP_PAYLOAD_LEN(f.state.out[0]) != 1 ||
			(f.conn->flags & II_TCP_CONN_FLAGS_SET_PROBE) ||
			f.conn->sent_seq - f.conn->acked_seq != 1) {
		*why = "SWS override did not send a normal one-octet segment";
		return 0;
	}
	return 1;
}

static int test_sws_push_followed_by_fin(const char **why,
		uint16_t effective_mss)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *payload;
	void *opaque = &f.state;
	const uint16_t data_len = 100;
	unsigned int i;
	void *data_pkt = NULL, *fin_pkt = NULL;

	if (!fixture_init(&f) || effective_mss <= data_len * 2U)
		return 0;
	fixture_prepare_sender(&f);
	/* Remember a window whose half is larger than data_len, then offer just
	 * enough space for the pushed data and its following FIN. */
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = effective_mss;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = data_len + 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	free_output(&f.state);
	test_event_log_clear(&f.state);

	payload = iip_ops_pkt_alloc(opaque);
	if (!payload)
		return 0;
	memset(iip_ops_pkt_get_data(payload, opaque), 0x5a, data_len);
	iip_ops_pkt_set_len(payload, data_len, opaque);
	if (test_api_send(f.ws, f.conn, payload, 0, opaque) == 0xffff ||
			test_api_close(f.ws, f.conn, opaque) == 0xffff)
		return 0;
	fixture_run_timers(&f);
	for (i = 0; i < f.state.out_cnt; i++) {
		if (PB_TCP_PAYLOAD_LEN(f.state.out[i]) == data_len &&
				PB_TCP_HDR_HAS_PSH(f.state.out[i]))
			data_pkt = f.state.out[i];
		if (PB_TCP_HDR_HAS_FIN(f.state.out[i]))
			fin_pkt = f.state.out[i];
	}
	if (!data_pkt || !fin_pkt || (f.conn->flags & II_TCP_CONN_FLAGS_SET_PROBE) ||
			!ip4_checksum_valid(data_pkt) || !checksum_valid(data_pkt) ||
			!ip4_checksum_valid(fin_pkt) || !checksum_valid(fin_pkt)) {
		*why = "a FIN-only tail hid the PUSH state of queued data";
		return 0;
	}
	return 1;
}

static enum result test_sender_sws_avoidance(const char **why)
{
	struct fixture f;
	struct fixture large;
	struct tcp_packet_spec spec;
	void *payload;
	void *opaque = &f.state;
	void *large_opaque = &large.state;
	uint16_t effective_mss;
	uint16_t large_payload_len;
	unsigned int i;
	void *full_segment = NULL;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	/* Eff.snd.MSS = min(SendMSS + 20, MMS_S) - TCPhdrsize - IPoptionsize
	 * (RFC 9293 Section 3.7.1), where MMS_S follows from the path MTU and
	 * TCPhdrsize includes the Timestamps option carried on every segment
	 * once it has been negotiated. */
	effective_mss = f.conn->mss;
	if (f.conn->path_mtu - 40U < effective_mss)
		effective_mss = f.conn->path_mtu - 40U;
	if (II_CONF_TCP_OPT_TS_OK &&
			(f.conn->flags & II_TCP_CONN_FLAGS_OPT_SET_TS))
		effective_mss -= 12U;
	if (!effective_mss)
		return RESULT_FAIL;

	/* Establish a maximum observed send window, then have the peer advertise
	 * only one usable octet.  With no outstanding data, neither a full-sized
	 * segment nor half the maximum window can be sent. */
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = effective_mss;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	free_output(&f.state);
	test_event_log_clear(&f.state);
	payload = iip_ops_pkt_alloc(opaque);
	if (!payload)
		return RESULT_FAIL;
	memset(iip_ops_pkt_get_data(payload, opaque), 0x5a, effective_mss);
	iip_ops_pkt_set_len(payload, effective_mss, opaque);
	if (test_api_send(f.ws, f.conn, payload, 0, opaque) == 0xffff)
		return RESULT_FAIL;
	fixture_run_timers(&f);
	if (f.state.out_cnt != 0 || !test_ring_end(f.ws, &f.conn->tx_ring, 0) ||
			test_ring_end(f.ws, &f.conn->sent_ring, 0)) {
		*why = "sender emitted a tiny segment for a one-octet window advance";
		return RESULT_FAIL;
	}

	/* Once a complete effective-MSS window is offered, the queued data must
	 * no longer be held back by sender SWS avoidance. */
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->acked_seq;
	spec.window = effective_mss;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	for (i = 0; i < f.state.out_cnt; i++) {
		if (PB_TCP_PAYLOAD_LEN(f.state.out[i]) == effective_mss) {
			full_segment = f.state.out[i];
			break;
		}
	}
	if (!full_segment || !ip4_checksum_valid(full_segment) ||
			!checksum_valid(full_segment)) {
		*why = "sender did not release a full segment after the window opened";
		return RESULT_FAIL;
	}

	/* A large application write must not make a one-octet usable window look
	 * like permission to send a full-sized segment.  In particular, the SWS
	 * decision must use min(D, U), not the complete sequence range already
	 * assigned to sent and unsent data. */
	if (!fixture_init(&large))
		return RESULT_FAIL;
	fixture_prepare_sender(&large);
	large_payload_len = large.conn->mss;
	if (large_payload_len > 2048U - 8U * sizeof(long)) {
		*why = "configured MSS exceeds the test packet data capacity";
		return RESULT_FAIL;
	}
	fixture_incoming_spec(&large, &spec, 0, NULL, 0);
	spec.ack_seq = large.conn->acked_seq;
	spec.window = effective_mss;
	fixture_deliver(&large, build_tcp_packet(&spec, &large.state));
	fixture_incoming_spec(&large, &spec, 0, NULL, 0);
	spec.ack_seq = large.conn->acked_seq;
	spec.window = 1;
	fixture_deliver(&large, build_tcp_packet(&spec, &large.state));
	free_output(&large.state);
	test_event_log_clear(&large.state);
	payload = iip_ops_pkt_alloc(large_opaque);
	if (!payload)
		return RESULT_FAIL;
	memset(iip_ops_pkt_get_data(payload, large_opaque), 0x5a,
			large_payload_len);
	iip_ops_pkt_set_len(payload, large_payload_len, large_opaque);
	if (test_api_send(large.ws, large.conn, payload, 0,
			large_opaque) == 0xffff)
		return RESULT_FAIL;
	fixture_run_timers(&large);
	if (large.state.out_cnt != 0 || !test_ring_end(large.ws, &large.conn->tx_ring, 0) ||
			test_ring_end(large.ws, &large.conn->sent_ring, 0) || (large.conn->flags & II_TCP_CONN_FLAGS_SET_PROBE)) {
		*why = "queued data size bypassed SWS avoidance for a one-octet window";
		return RESULT_FAIL;
	}
	/* Exact override timing is covered by a separately selected profile. */
	return RESULT_PASS;
}

/*
 * Emit one ACK so that RCV.WND is fixed on the wire before a window-edge
 * test.  Decode the window field with conn->ws, matching the shift passed
 * to ii_tcp_compute_win by the implementation.
 */
static int fixture_advertise_window(struct fixture *f, uint32_t expected)
{
	void *pkt = fixture_packet(f, 0, 0, 0);
	uint32_t window;
	int ok;

	if (!pkt)
		return 0;
	window = (uint32_t)ii_ntohs(PB_TCP(pkt)->win_be) << f->conn->ws;
	ok = window == expected;
	if (!ok)
		fprintf(stderr, "advertised window %u, expected %u\n",
				window, expected);
	iip_ops_pkt_free(pkt, &f->state);
	return ok;
}

static int test_receive_window_right_edge(const char **why)
{
	struct fixture crossing;
	struct fixture outside;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0, 1 };
	struct ii_pb *p;

	/* [255, 257) crosses the right edge of the receive window [0, 256).
	 * Only the octet at sequence number 255 may remain queued. */
	if (!fixture_init(&crossing))
		return 0;
	crossing.conn->flags |= II_TCP_CONN_FLAGS_SACK_OK;
	crossing.conn->buf.capacity = 256;
	crossing.conn->buf.used = 0;
	if (!fixture_advertise_window(&crossing, 256)) {
		*why = "the fixture could not advertise a 256-octet receive window";
		return 0;
	}
	fixture_incoming_spec(&crossing, &spec, 255, payload,
			sizeof(payload));
	fixture_deliver(&crossing,
			build_tcp_packet(&spec, &crossing.state));
	p = test_ring_end(crossing.ws, &crossing.conn->pending_ring, 0);
	if (!p || PB_TCP_PAYLOAD_LEN(p->part_pkt[0]) - p->tcp.inc_head -
			p->tcp.dec_tail != 1 || p->tcp.dec_tail != 1) {
		*why = "receiver did not trim an out-of-order segment at the window right edge";
		return 0;
	}

	/* A non-empty segment beginning exactly at the right edge is entirely
	 * outside the receive window and must not be queued. */
	if (!fixture_init(&outside))
		return 0;
	outside.conn->flags |= II_TCP_CONN_FLAGS_SACK_OK;
	outside.conn->buf.capacity = 256;
	outside.conn->buf.used = 0;
	if (!fixture_advertise_window(&outside, 256)) {
		*why = "the fixture could not advertise a 256-octet receive window";
		return 0;
	}
	fixture_incoming_spec(&outside, &spec, 256, payload, 1);
	fixture_deliver(&outside,
			build_tcp_packet(&spec, &outside.state));
	if (test_ring_end(outside.ws, &outside.conn->pending_ring, 0)) {
		*why = "receiver queued a segment beginning at the window right edge";
		return 0;
	}
	return 1;
}

static enum result test_receive_window_boundary(const char **why)
{
	return test_receive_window_right_edge(why) ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_receiver_sws_accounting_profile(const char **why)
{
    struct fixture boundary;
    uint32_t effective_mss;
	/* Receiver SWS avoidance opens the window at, not only above, the
	 * min(RCV.BUFF/2, Eff.snd.MSS) threshold.  Eff.snd.MSS excludes the
	 * TCP options actually carried (RFC 9293 Section 3.7.1); the fixture
	 * sends Timestamps, so with MSS 300 and MTU 1500 the threshold is
	 * 300 - 12 = 288 octets. */
	if (!fixture_init(&boundary))
		return RESULT_FAIL;
	if (II_CONF_TCP_OPT_TS_OK) boundary.conn->flags |= II_TCP_CONN_FLAGS_OPT_SET_TS;
	{
		uint32_t threshold = 300U -
			((boundary.conn->flags & II_TCP_CONN_FLAGS_OPT_SET_TS) ?
			 12U : 0U);
		if (threshold > 4096U / 2U)
			threshold = 4096U / 2U;
		boundary.conn->buf.capacity = 4096;
		boundary.conn->buf.used = threshold - 1U;
		boundary.conn->buf.adv_cnt = 0;
		boundary.conn->mss = 300;
		boundary.conn->path_mtu = 1500;
		test_api_consumed(boundary.ws, boundary.conn, threshold - 1U,
				&boundary.state);
		if (boundary.conn->buf.used != threshold - 1U ||
				boundary.conn->buf.adv_cnt != threshold - 1U) {
			fprintf(stderr, "receiver SWS: threshold=%u, window opened after %u octets\n",
					threshold, threshold - 1U);
			*why = "receiver advertised a window update below the SWS threshold";
			return RESULT_FAIL;
		}
	}
	/* Simulate receiving and then consuming the final octet needed to reach
	 * the exact threshold. */
	boundary.conn->buf.used++;
	test_api_consumed(boundary.ws, boundary.conn, 1,
			&boundary.state);
	if (boundary.conn->buf.used ||
			boundary.conn->buf.adv_cnt) {
		*why = "receiver did not update the window at the exact SWS threshold";
		return RESULT_FAIL;
	}

	/* The SWS threshold uses the amount of data that actually fits after TCP
	 * options.  With PMTU 330 and timestamps, this is 278 octets. */
	effective_mss = 330U - sizeof(struct iip_ip4_hdr) -
		sizeof(struct iip_tcp_hdr) -
		(II_CONF_TCP_OPT_TS_OK ? 12U : 0U);
	if (effective_mss > 300U -
			(II_CONF_TCP_OPT_TS_OK ? 12U : 0U))
		effective_mss = 300U -
			(II_CONF_TCP_OPT_TS_OK ? 12U : 0U);
	boundary.conn->buf.capacity = 4096;
	boundary.conn->buf.used = effective_mss;
	boundary.conn->buf.adv_cnt = 0;
	boundary.conn->mss = 300;
	boundary.conn->path_mtu = 330;
	test_api_consumed(boundary.ws, boundary.conn, effective_mss,
			&boundary.state);
	if (boundary.conn->buf.used ||
			boundary.conn->buf.adv_cnt) {
		*why = "receiver SWS threshold did not account for TCP options";
		return RESULT_FAIL;
	}

    return RESULT_PASS;
}

static enum result test_receiver_sws_avoidance(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	void *opaque = &f.state;
	void *received_ack = NULL, *consumed_pkt;
	uint32_t initial_ack, initial_window, initial_right_edge;
	uint32_t received_ack_seq, received_window, received_right_edge;
	uint32_t consumed_window;
	uint32_t scale_slop;
	unsigned int i, shift;


	/* This white-box fixture does not negotiate Window Scale.  Use the
	 * unscaled profile explicitly; never infer permission from output. */
	shift = 0;
	scale_slop = (1U << shift) - 1U;


	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	f.state.defer_payload_consumption = 1;
	initial_ack = f.conn->ack_seq;
	/* Measure the initially advertised edge; advertising less than capacity is legal.
     * The shift stays independently fixed at zero (no negotiation). */
    void *initial_pkt = fixture_packet(&f, 0, 0, 0);
    if (!initial_pkt) return RESULT_ERROR;
    initial_window = ii_ntohs(PB_TCP(initial_pkt)->win_be);
    iip_ops_pkt_free(initial_pkt, opaque);
    if (!initial_window) { *why = "initial receive window is zero; SWS scenario unavailable"; return RESULT_INCONCLUSIVE; }
	initial_right_edge = initial_ack + initial_window;

	fixture_incoming_spec(&f, &spec, initial_ack, payload,
			sizeof(payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	for (unsigned ms = 0; ms < 499 && !f.state.out_cnt; ms++) {
		fixture_advance_ms(&f, 1);
	}
	for (i = 0; i < f.state.out_cnt; i++) {
		if (PB_TCP_HDR_HAS_ACK(f.state.out[i]) &&
				ii_ntohl(PB_TCP(f.state.out[i])->ack_seq_be) ==
				initial_ack + sizeof(payload)) {
			received_ack = f.state.out[i];
			break;
		}
	}
	if (!received_ack) {
		*why = "receiver did not emit an observable ACK for the SWS test";
		return RESULT_FAIL;
	}
	received_ack_seq = ii_ntohl(PB_TCP(received_ack)->ack_seq_be);
	received_window =
		(uint32_t)ii_ntohs(PB_TCP(received_ack)->win_be) << shift;
	received_right_edge = received_ack_seq + received_window;
	if (received_right_edge + scale_slop < initial_right_edge) {
		*why = "receive-window shrink (SHOULD NOT); SWS observation cannot be isolated";
		return RESULT_INCONCLUSIVE;
	}

	/* Consuming this one-octet payload must not be treated as releasing one
	 * complete MSS-sized receive buffer. */
	if (!f.state.deferred_payload_len) {
		*why = "receiver did not retain the deferred payload length";
		return RESULT_FAIL;
	}
	test_api_consumed(f.ws, f.conn,
			f.state.deferred_payload_len, opaque);
	f.state.deferred_payload_len = 0;
	consumed_pkt = fixture_packet(&f, 0, 0, 0);
	if (!consumed_pkt)
		return RESULT_FAIL;
	consumed_window =
		(uint32_t)ii_ntohs(PB_TCP(consumed_pkt)->win_be) << shift;
	iip_ops_pkt_free(consumed_pkt, opaque);
	if (consumed_window > received_window + scale_slop) {
		*why = "consuming one octet caused a small receive-window update";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}


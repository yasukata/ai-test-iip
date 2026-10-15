/* Send capacity, Nagle, retransmission, and congestion control.
 * Included in dependency order by test_tcp.h.
 */

/* This tests a zero effective send MSS, separately from a received MSS=0. */
static enum result zero_send_mss_case(uint16_t mss, uint8_t timestamps,
		const char **why)
{
	struct fixture f;
	struct ii_pb *p;
	void *payload;
	uint32_t sent_seq_before;
	enum iip_rc rc;
	int progress_ok, closing;

	if (!fixture_init(&f)) {
		*why = "fixture initialization failed";
		return RESULT_FAIL;
	}
	f.conn->mss = mss;
	if (timestamps)
		f.conn->flags |= II_TCP_CONN_FLAGS_OPT_SET_TS;
	else
		f.conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
	payload = iip_ops_pkt_alloc(&f.state);
	if (!payload) {
		free(f.ws);
		*why = "payload allocation failed";
		return RESULT_FAIL;
	}
	memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, 4);
	iip_ops_pkt_set_len(payload, 4, &f.state);
	test_api_push(f.ws, f.conn, payload, 0, 1, 0, 0, 0,
			NULL, 0, &f.state);
	free_output(&f.state);
	p = test_ring_end(f.ws, &f.conn->tx_ring, 0);
	if (!p || ii_pb_ring_num_used(&f.conn->tx_ring) != 1) {
		*why = "payload was not queued before zero-MSS transmission";
		return RESULT_FAIL;
	}
	sent_seq_before = f.conn->sent_seq;
	rc = ii_tcp_conn_xmit_queued_data(f.ws,
			test_conn_id(f.ws, f.conn), 4, &f.state);
	progress_ok = !f.state.out_cnt &&
		f.conn->sent_seq == sent_seq_before && p->tcp.sent_bytes == 0 &&
		ii_pb_ring_num_used(&f.conn->tx_ring) == 1 &&
		test_ring_end(f.ws, &f.conn->tx_ring, 0) == p &&
		ii_pb_ring_num_used(&f.conn->sent_ring) == 0;
	closing = !!(f.conn->flags & II_TCP_CONN_FLAGS_CLOSING);
	/* Finish the deferred close and verify its externally visible callback
	 * and all four descriptor queues. ASan also detects invalid cleanup. */
	if (closing && ii_tcp_conn_close_check(f.ws,
			test_conn_id(f.ws, f.conn), &f.state) != IIP_ERR_OK) {
		*why = "zero-MSS connection cleanup failed";
		return RESULT_FAIL;
	}
	if (rc != IIP_ERR_OK)
		*why = "zero-MSS transmission escaped as a stack error";
	else if (!progress_ok)
		*why = "zero-MSS transmission emitted data or advanced unsent queue/sequence state";
	else if (!closing)
		*why = "zero-MSS transmission did not request connection closure";
	else if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_CLOSED) != 1 ||
			ii_pb_ring_num_used(&f.conn->rx_ring) ||
			ii_pb_ring_num_used(&f.conn->tx_ring) ||
			ii_pb_ring_num_used(&f.conn->sent_ring) ||
			ii_pb_ring_num_used(&f.conn->pending_ring))
		*why = "zero-MSS close did not notify once and clear all queues";
	else {
		free_output(&f.state);
		free(f.ws);
		return RESULT_PASS;
	}
	free_output(&f.state);
	free(f.ws);
	return RESULT_FAIL;
}

static enum result test_zero_effective_send_mss(const char **why)
{
	if (!getenv("IIP_TEST_STRICT_API_CONTRACT")) {
		*why = "optional strict iip API contract not selected; not an RFC requirement";
		return RESULT_SKIP;
	}

	/* Cover zero, subtraction underflow, and an exactly zero difference. */
	if (zero_send_mss_case(0, 0, why) != RESULT_PASS)
		return RESULT_FAIL;
	if (II_CONF_TCP_OPT_TS_OK) {
		if (zero_send_mss_case(1, 1, why) != RESULT_PASS ||
				zero_send_mss_case(12, 1, why) != RESULT_PASS)
			return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_tcp_capacity_failure_is_atomic(const char **why)
{
	if (!getenv("IIP_TEST_STRICT_API_CONTRACT")) {
		*why = "optional strict iip API contract not selected; not an RFC requirement";
		return RESULT_SKIP;
	}

	struct fixture f;
	struct ii_pb *p;
	void *payload;
	uint32_t seq_before, sent_seq_before;
	uint16_t result;

	if (!fixture_init(&f)) {
		*why = "fixture initialization failed";
		return RESULT_FAIL;
	}
	payload = fixture_oversized_tcp_payload(&f);
	if (!payload || test_api_send(f.ws, f.conn, payload, 0, &f.state)) {
		*why = "failed to enqueue payload before capacity injection";
		return RESULT_FAIL;
	}
	p = test_ring_end(f.ws, &f.conn->tx_ring, 0);
	seq_before = f.conn->seq;
	sent_seq_before = f.conn->sent_seq;
	result = fixture_transmit_with_capacity_failure(&f, p, 32);
	if (result != UINT16_MAX) {
		*why = "capacity failure was not reported";
		return RESULT_FAIL;
	}
	if (f.state.out_cnt) {
		*why = "a preceding segment was transmitted before an atomic transmission failure";
		return RESULT_FAIL;
	}
	if (test_ring_end(f.ws, &f.conn->tx_ring, 0) != p ||
			test_ring_end(f.ws, &f.conn->tx_ring, 1) != p ||
			ii_pb_ring_num_used(&f.conn->tx_ring) != 1) {
		*why = "accepted payload queue changed after transmission failure";
		return RESULT_FAIL;
	}
	if (f.conn->seq != seq_before || f.conn->sent_seq != sent_seq_before) {
		*why = "send sequence advanced after an atomic transmission failure";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_tcp_payload_capacity_failure_frees_clone(
		const char **why)
{
	struct fixture f;
	void *payload;
	uint16_t result;
	int clone_freed;

	if (!fixture_init(&f)) {
		*why = "fixture initialization failed";
		return RESULT_FAIL;
	}
	payload = fixture_oversized_tcp_payload(&f);
	if (!payload) {
		*why = "payload allocation failed";
		return RESULT_FAIL;
	}

	packet_clone_tracking = 1;
	packet_tracked_clone = NULL;
	packet_tracked_clone_freed = 0;
	if (test_api_send(f.ws, f.conn, payload, 0, &f.state)) {
		*why = "failed to enqueue payload before capacity injection";
		return RESULT_FAIL;
	}
	result = fixture_transmit_with_capacity_failure(&f,
		test_ring_end(f.ws, &f.conn->tx_ring, 1), 66);
	clone_freed = !packet_tracked_clone || packet_tracked_clone_freed;
	packet_clone_tracking = 0;

	if (!clone_freed && packet_tracked_clone)
		iip_ops_pkt_free(packet_tracked_clone, &f.state);
	packet_tracked_clone = NULL;
	packet_tracked_clone_freed = 0;
	if (result != 0xffff) {
		*why = "payload capacity failure was not reported";
		return RESULT_FAIL;
	}
	if (!clone_freed) {
		*why = "a clone allocated during transmission leaked after capacity failure";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int fixture_queue_data_at_zero_window(struct fixture *f)
{
	void *payload;

	fixture_prepare_sender(f);
	f->conn->peer_win = 0;
	payload = iip_ops_pkt_alloc(&f->state);
	if (!payload)
		return 0;
	*(uint8_t *)iip_ops_pkt_get_data(payload, &f->state) = 0x5a;
	iip_ops_pkt_set_len(payload, 1, &f->state);
	if (test_api_send(f->ws, f->conn, payload, 0, &f->state) == 0xffff)
		return 0;
	fixture_run_timers(f);
	return f->state.out_cnt == 0 && test_ring_end(f->ws, &f->conn->tx_ring, 0) != NULL &&
		test_ring_end(f->ws, &f->conn->sent_ring, 0) == NULL;
}

static enum result test_tcp_capacity_failure_preserves_existing_queue(
		const char **why)
{
	struct fixture f;
	struct ii_pb *pending, *queued;
	void *pending_pkt;
	void *payload;
	uint32_t seq_before;
	uint16_t result;

	if (!fixture_init(&f)) {
		*why = "fixture initialization failed";
		return RESULT_FAIL;
	}
	if (!fixture_queue_data_at_zero_window(&f)) {
		*why = "failed to prepare an existing queued segment";
		return RESULT_FAIL;
	}
	pending = test_ring_end(f.ws, &f.conn->tx_ring, 0);
	pending_pkt = pending->part_pkt[0];

	payload = fixture_oversized_tcp_payload(&f);
	if (!payload) {
		*why = "payload allocation failed";
		return RESULT_FAIL;
	}

	if (test_api_send(f.ws, f.conn, payload, 0, &f.state)) {
		*why = "failed to enqueue payload before capacity injection";
		return RESULT_FAIL;
	}
	queued = test_ring_end(f.ws, &f.conn->tx_ring, 1);
	seq_before = ii_htonl(f.conn->seq);
	result = fixture_transmit_with_capacity_failure(&f, queued, 32);

	if (result != 0xffff) {
		*why = "capacity failure was not reported";
		return RESULT_FAIL;
	}
	if (test_ring_end(f.ws, &f.conn->tx_ring, 0) != pending || test_ring_end(f.ws, &f.conn->tx_ring, 1) != queued) {
		*why = "existing send queue endpoints changed after failure";
		return RESULT_FAIL;
	}
	if (pending->part_pkt[0] != pending_pkt) {
		*why = "existing queued packet was released after failure";
		return RESULT_FAIL;
	}
	if (ii_pb_ring_num_used(&f.conn->tx_ring) != 2) {
		*why = "existing send queue links changed after failure";
		return RESULT_FAIL;
	}
	if (ii_htonl(f.conn->seq) != seq_before) {
		*why = "send sequence advanced after an atomic send failure";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static unsigned int fixture_wait_for_zero_window_probes(struct fixture *f,
		unsigned int wanted, unsigned int max_seconds,
		uint32_t probe_at_seconds[])
{
	unsigned int elapsed, found = 0;

	for (elapsed = 1; elapsed <= max_seconds && found < wanted; elapsed++) {
		unsigned int i;
		fake_clock_advance_sec(&f->state, 1);
		fixture_run_timers(f);
		for (i = 0; i < f->state.out_cnt && found < wanted; i++) {
			void *pkt = f->state.out[i];
			/*
			 * RFC 9293 Section 3.8.6.1: a probe carries at least one
			 * octet of new data, or retransmits data to confirm the
			 * window.  Neither the exact length nor a trailing FIN
			 * is constrained.
			 */
			if (PB_TCP_HDR_HAS_ACK(pkt) &&
					PB_TCP_PAYLOAD_LEN(pkt) >= 1 &&
					!PB_TCP_HDR_HAS_SYN(pkt) &&
					!PB_TCP_HDR_HAS_RST(pkt)) {
				probe_at_seconds[found] = elapsed;
				found++;
			}
		}
		free_output(&f->state);
	}
	return found;
}

/*
 * Two one-octet writes on an established connection with an open window.
 * Returns the number of segments emitted for the second write before any
 * ACK of the first (0 = held, 1 = sent), or -1 on a precondition failure.
 * When held, *released reports whether the ACK of the first octet sent it.
 */
static int nagle_second_small_write(struct fixture *f, int disable, int *released)
{
	struct tcp_packet_spec spec;
	uint32_t first_ack;
	int sent;
	if (!fixture_init(f))
		return -1;
	fixture_prepare_sender(f);
	f->conn->cc.win = 8;
	if (disable >= 0)
		IIP_EX_TCP_SET_NAGLE_DISABLED(f->ws, f->conn, disable, &f->state);
	if (!fixture_send_data(f, 1) || f->state.out_cnt != 1)
		return -1;
	first_ack = f->conn->acked_seq + 1;
	free_output(&f->state);
	test_event_log_clear(&f->state);
	/* Below the 1 s sender-SWS override and below any RTO. */
	fake_clock_advance_ms(&f->state, 200);
	if (!fixture_send_data(f, 1) && test_ring_end(f->ws, &f->conn->tx_ring, 0) == NULL)
		return -1;
	if (f->state.out_cnt > 1)
		return -1;
	sent = (int)f->state.out_cnt;
	if (sent == 1 && PB_TCP_PAYLOAD_LEN(f->state.out[0]) != 1)
		return -1;
	if (released) {
		*released = 0;
		if (!sent) {
			free_output(&f->state);
			fixture_incoming_spec(f, &spec, 0, NULL, 0);
			spec.ack_seq = first_ack;
			fixture_deliver(f, build_tcp_packet(&spec, &f->state));
			*released = f->state.out_cnt == 1 &&
				PB_TCP_PAYLOAD_LEN(f->state.out[0]) == 1;
		}
	}
	return sent;
}

/*
 * RFC 9293 MUST-17 (Section 3.7.4): an application MUST be able to disable
 * the Nagle algorithm on an individual connection.  iip exposes the state
 * as II_TCP_CONN_FLAGS_NAGLE_DISABLED; the harness binding is
 * IIP_EX_TCP_SET_NAGLE_DISABLED (test_backend.h).  With the control set, a
 * second small write must leave without waiting for the first ACK.
 * Whether Nagle is implemented at all is SHLD-7, checked separately.
 */
static enum result test_disable_nagle(const char **why)
{
#ifndef IIP_EX_TCP_SET_NAGLE_DISABLED
	*why = "no Nagle-disable control is exposed; Nagle is treated as not implemented";
	return RESULT_SKIP;
#else
	struct fixture f, other;
	int sent;
	if (!fixture_init(&f))
		return RESULT_ERROR;
	if (f.conn->flags & II_TCP_CONN_FLAGS_NAGLE_DISABLED) {
		*why = "Nagle is disabled by default on a new connection";
		return RESULT_FAIL;
	}
	/* The control is per connection and reversible. */
	if (!fixture_init(&other))
		return RESULT_ERROR;
	IIP_EX_TCP_SET_NAGLE_DISABLED(f.ws, f.conn, 1, &f.state);
	if (!(f.conn->flags & II_TCP_CONN_FLAGS_NAGLE_DISABLED) ||
			(other.conn->flags & II_TCP_CONN_FLAGS_NAGLE_DISABLED)) {
		*why = "the Nagle-disable control is not per connection";
		return RESULT_FAIL;
	}
	IIP_EX_TCP_SET_NAGLE_DISABLED(f.ws, f.conn, 0, &f.state);
	if (f.conn->flags & II_TCP_CONN_FLAGS_NAGLE_DISABLED) {
		*why = "the Nagle-disable control cannot be cleared";
		return RESULT_FAIL;
	}
	sent = nagle_second_small_write(&f, 1, NULL);
	if (sent < 0) {
		*why = "precondition: small writes were not emitted as expected";
		return RESULT_ERROR;
	}
	if (sent != 1) {
		*why = "with Nagle disabled, a second small segment waited for an ACK";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
#endif
}

/*
 * RFC 9293 SHLD-7 (Section 3.7.4): a TCP implementation SHOULD implement
 * the Nagle algorithm.  With unacknowledged data outstanding, a new
 * segment smaller than Eff.snd.MSS is held until that data is ACKed.
 */
static enum result test_nagle_algorithm(const char **why)
{
	struct fixture f;
	int released = 0;
	int sent = nagle_second_small_write(&f, -1, &released);
	if (sent < 0) {
		*why = "precondition: small writes were not emitted as expected";
		return RESULT_ERROR;
	}
	if (sent == 1) {
		*why = "a second small segment was sent while the first was unacknowledged (Nagle not applied)";
		return RESULT_TODO;
	}
	if (!released) {
		*why = "a small segment held by Nagle was not sent when the outstanding data was ACKed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_karn_rtt_sampling(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	uint32_t initial_rto, srtt_before, rttvar_before;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	/*
	 * Karn's algorithm forbids RTT samples from retransmitted segments
	 * only when the ACK is ambiguous.  With timestamps, RFC 6298 Section 3
	 * and RFC 7323 permit such samples, so exercise the ambiguous case:
	 * timestamps are disabled and the ACK carries no TSecr.
	 */
	f.conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
	f.conn->rtt.srtt = 10;
	f.conn->rtt.rttvar = 5;
	if (!fixture_send_data(&f, 1))
		return RESULT_FAIL;
	initial_rto = f.conn->rto_ms;
	free_output(&f.state);
	test_event_log_clear(&f.state);

	/* Force an RTO retransmission, then ACK that retransmitted segment. */
	fixture_advance_ms(&f, (uint64_t)initial_rto + 1);
	if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION,
			TEST_RETRANS_TIMEOUT) != 1 || f.state.out_cnt != 1)
		return RESULT_FAIL;
	if (option_find(f.state.out[0], 8)) {
		*why = "retransmission carried a timestamp although timestamps were disabled";
		return RESULT_FAIL;
	}
	srtt_before = f.conn->rtt.srtt;
	rttvar_before = f.conn->rtt.rttvar;
	free_output(&f.state);
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.ack_seq = f.conn->seq;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));

	if (f.conn->rtt.srtt != srtt_before ||
			f.conn->rtt.rttvar != rttvar_before) {
		fprintf(stderr, "Karn RTT sampling: estimator changed from %u/%u to %u/%u after retransmission ACK\n",
				srtt_before, rttvar_before, f.conn->rtt.srtt,
				f.conn->rtt.rttvar);
		*why = "RTT estimator was updated from an ambiguous ACK for a retransmitted segment";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int congestion_growth_scenario(uint16_t cwnd, uint16_t ssthresh,
		uint16_t min_cwnd, uint16_t max_cwnd)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	if (!fixture_init(&f))
		return 0;
	fixture_prepare_sender(&f);
	f.conn->cc.win = cwnd;
	f.conn->cc.ssthresh = ssthresh;
	if (!fixture_send_data(&f, 1))
		return 0;
	free_output(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.conn->acked_seq == f.conn->seq &&
		f.conn->cc.win >= min_cwnd && f.conn->cc.win <= max_cwnd;
}

static int timeout_backoff_scenario(void)
{
	struct fixture f;
	const struct test_event *loss, *first, *second;
	uint32_t initial_rto, first_rto, second_rto, seq;
	if (!fixture_init(&f))
		return 0;
	fixture_prepare_sender(&f);
	f.conn->cc.win = 8;
	f.conn->cc.ssthresh = 16;
	seq = f.conn->seq;
	if (!fixture_send_data(&f, 1))
		return 0;
	if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0) != 0)
		return 0;
	initial_rto = f.conn->rto_ms;
	if (!initial_rto)
		return 0;
	free_output(&f.state);
	test_event_log_clear(&f.state);

	fixture_advance_ms(&f, (uint64_t)initial_rto + 1);
	first_rto = initial_rto <= 30000U ? initial_rto * 2U : 60000U;
	loss = test_event_nth(&f.state, TEST_EVENT_LOSS_DETECTED,
			TEST_LOSS_TIMEOUT, 0);
	first = test_event_nth(&f.state, TEST_EVENT_RETRANSMISSION,
			TEST_RETRANS_TIMEOUT, 0);
	/*
	 * RFC 5681 Section 3.1: after an RTO, ssthresh MUST be no more than
	 * max(FlightSize / 2, 2 * SMSS) (equation (4)) and cwnd MUST be no more
	 * than the loss window of one segment.  Only one segment is in flight
	 * here, so the bound is two segments.  Basing ssthresh on cwnd is the
	 * mistake the RFC explicitly warns against.
	 */
	if (loss && (loss->value[1] > 1 || loss->value[3] > 2))
		fprintf(stderr, "MUST-19: after RTO cwnd %u->%u (max 1), ssthresh %u->%u (max max(FlightSize/2, 2*SMSS) = 2)\n",
				(unsigned int)loss->value[0], (unsigned int)loss->value[1],
				(unsigned int)loss->value[2], (unsigned int)loss->value[3]);
	if (!loss || !first || loss->value[0] != 8 || loss->value[1] > 1 ||
			loss->value[2] != 16 || loss->value[3] > 2 ||
			first->value[0] != seq || first->value[1] != 1 ||
			first->value[2] < first_rto || first->value[3] != 1)
		return 0;
	free_output(&f.state);

	first_rto = f.conn->rto_ms;
	fixture_advance_ms(&f, (uint64_t)first_rto + 1);
	second_rto = first_rto <= 30000U ? first_rto * 2U : 60000U;
	second = test_event_nth(&f.state, TEST_EVENT_RETRANSMISSION,
			TEST_RETRANS_TIMEOUT, 1);
	if (!second || second->value[0] != seq || second->value[1] != 2 ||
			second->value[2] < second_rto ||
			test_event_count(&f.state, TEST_EVENT_LOSS_DETECTED,
					TEST_LOSS_TIMEOUT) != 1 ||
			second->at_ns - first->at_ns < (uint64_t)first_rto * 1000000ULL)
		return 0;
	free_output(&f.state);
	return 1;
}

static int retransmission_and_congestion_scenario(void)
{
	/*
	 * MUST-19 covers exponential backoff, slow start, and congestion
	 * avoidance.  Fast retransmit/fast recovery (RFC 5681 Section 3.2) is
	 * a SHOULD, and SACK-based loss recovery (RFC 6675) is optional, so
	 * neither is part of this mandatory requirement.
	 *
	 * When cwnd == ssthresh, RFC 5681 Section 3.1 allows either slow start
	 * or congestion avoidance, so cwnd may stay at 8 or grow to 9.
	 */
	return congestion_growth_scenario(1, 8, 1, 2) &&
		congestion_growth_scenario(8, 8, 8, 9) &&
		timeout_backoff_scenario();
}

static enum result test_retransmission_and_congestion(const char **why)
{
	pid_t child;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(retransmission_and_congestion_scenario() ? 0 : 1);
	if (!wait_test_child(child, 3000)) {
		*why = "slow start, RTO backoff, or post-RTO cwnd/ssthresh bound failed (see log)";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_r1_r2_failure_handling(const char **why)
{
	struct fixture f;
	uint32_t data_seq;
	uint32_t r1;
	uint32_t r2;
	unsigned int i;
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	r1 = f.conn->retrans_r1;
	r2 = f.conn->retrans_r2;
	if (!r1 || r2 <= r1)
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	if (!fixture_send_data(&f, 1))
		return RESULT_FAIL;
	if (output_count_ethertype(&f.state, 0x0800) != 1 ||
			output_count_ethertype(&f.state, 0x0806) != 0)
		return RESULT_FAIL;
	data_seq = ii_ntohl(PB_TCP(
			output_nth_ethertype(&f.state, 0x0800, 0))->seq_be);
	free_output(&f.state);
	test_event_log_clear(&f.state);

	for (i = 1; i <= r2; i++) {
		void *tcp_pkt;
		uint32_t rto_ms = f.conn->rto_ms;
		fixture_advance_ms(&f, (uint64_t)rto_ms + 1);
		tcp_pkt = output_nth_ethertype(&f.state, 0x0800, 0);
		if (f.conn->state != II_TCP_STATE_ESTABLISHED ||
				f.conn->retrans_cnt != i || !tcp_pkt ||
				output_count_ethertype(&f.state, 0x0800) != 1 ||
				output_count_ethertype(&f.state, 0x0806) != 0 ||
				ii_ntohl(PB_TCP(tcp_pkt)->seq_be) != data_seq ||
				PB_TCP_PAYLOAD_LEN(tcp_pkt) != 1 ||
				!checksum_valid(tcp_pkt) ||
				test_event_count(&f.state, TEST_EVENT_CALLBACK,
						TEST_CALLBACK_IP4_NEGATIVE_ADVICE) !=
					(i < r1 ? 0U : 1U))
			return RESULT_FAIL;
		free_output(&f.state);
	}

	if (!test_ring_end(f.ws, &f.conn->sent_ring, 0))
		return RESULT_FAIL;
	fake_clock_advance_ms(&f.state,
			(uint64_t)f.conn->rto_ms + 1);
	fixture_run_timers(&f);
	return f.conn->state == 0 && f.state.out_cnt == 0 &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_IP4_NEGATIVE_ADVICE) == 1 &&
		test_event_has_state_transition(&f.state, f.conn,
				II_TCP_STATE_ESTABLISHED, II_TCP_STATE_CLOSED) &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1
		? RESULT_PASS : RESULT_FAIL;
}

static int fixture_timeout_once(struct fixture *f)
{
	uint32_t rto_ms;
	if (!test_ring_end(f->ws, &f->conn->sent_ring, 0))
		return 0;
	rto_ms = f->conn->rto_ms;
	fake_clock_advance_ms(&f->state, (uint64_t)rto_ms + 1);
	fixture_run_timers(f);
	free_output(&f->state);
	return 1;
}

static enum result test_application_configurable_r2(const char **why)
{
	struct fixture short_r2, long_r2;
	const uint32_t short_limit = 4;
	const uint32_t long_limit = 5;
	unsigned int i;
	(void)why;
	if (!fixture_init(&short_r2) || !fixture_init(&long_r2))
		return RESULT_FAIL;
	fixture_prepare_sender(&short_r2);
	fixture_prepare_sender(&long_r2);
	test_set_retrans_r2(short_r2.ws, short_r2.conn, short_limit,
			&short_r2.state);
	test_set_retrans_r2(long_r2.ws, long_r2.conn, long_limit,
			&long_r2.state);
	if (!fixture_send_data(&short_r2, 1) ||
			!fixture_send_data(&long_r2, 1))
		return RESULT_FAIL;
	free_output(&short_r2.state);
	free_output(&long_r2.state);
	test_event_log_clear(&short_r2.state);
	test_event_log_clear(&long_r2.state);

	/* Both connections see the same number of timeouts. */
	for (i = 0; i <= short_limit; i++)
		if (!fixture_timeout_once(&short_r2) ||
				!fixture_timeout_once(&long_r2))
			return RESULT_FAIL;
	if (short_r2.conn->state != 0 ||
			long_r2.conn->state != II_TCP_STATE_ESTABLISHED ||
			long_r2.conn->retrans_cnt != short_limit + 1 ||
			test_event_count(&short_r2.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_CLOSED) != 1 ||
			test_event_count(&long_r2.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_CLOSED) != 0)
		return RESULT_FAIL;

	/* The other connection remains alive until its independently set R2. */
	while (long_r2.conn->state == II_TCP_STATE_ESTABLISHED)
		if (!fixture_timeout_once(&long_r2))
			return RESULT_FAIL;
	return long_r2.conn->state == 0 &&
		test_event_count(&short_r2.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_IP4_NEGATIVE_ADVICE) == 1 &&
		test_event_count(&long_r2.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_IP4_NEGATIVE_ADVICE) == 1 &&
		test_event_count(&long_r2.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1
		? RESULT_PASS : RESULT_FAIL;
}

/*
 * MUST-22 (RFC 9293 Section 3.8.3): the R1/R2 failure mechanism applies to
 * SYN segments as well.  R2 may be expressed as a count or as time, so do
 * not assume a particular number of retransmissions: every retransmission
 * must repeat the original SYN, and the attempt must eventually be abandoned
 * with a single close notification.  The minimum duration is MUST-23.
 *
 * Advance the virtual clock to just past each retransmission deadline rather
 * than in fixed small steps.  A SYN attempt may legitimately last several
 * minutes, and fixed 100 ms steps record one timer event per step, which
 * overflowed the event log and discarded the final close notification.
 */
static enum result test_syn_failure_mechanism(const char **why)
{
	struct fixture f;
	void *tcp_pkt;
	uint32_t syn_seq;
	unsigned int retransmissions = 0;
	uint64_t started_ns;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	f.conn->state = II_TCP_STATE_SYN_SENT;
	test_event_tcp_state_set(&f.state, f.conn, f.conn->state);
	test_api_push(f.ws, f.conn, NULL, 1, 0, 0, 0, 0, NULL,
			0, &f.state);
	fixture_run_timers(&f);
	tcp_pkt = output_nth_ethertype(&f.state, 0x0800, 0);
	if (output_count_ethertype(&f.state, 0x0800) != 1 || !tcp_pkt ||
			!PB_TCP_HDR_HAS_SYN(tcp_pkt) || PB_TCP_HDR_HAS_ACK(tcp_pkt) ||
			PB_TCP_PAYLOAD_LEN(tcp_pkt) != 0 || !checksum_valid(tcp_pkt))
		return RESULT_FAIL;
	syn_seq = ii_ntohl(PB_TCP(tcp_pkt)->seq_be);
	started_ns = f.state.now_ns;
	free_output(&f.state);
	test_event_log_clear(&f.state);

	while (f.conn->state == II_TCP_STATE_SYN_SENT &&
			f.state.now_ns - started_ns <= 3600ULL * 1000000000ULL) {
		unsigned int i;
		uint32_t rto_ms = f.conn->rto_ms;
		if (!rto_ms) {
			*why = "no retransmission timer was armed for the SYN";
			return RESULT_FAIL;
		}
		fixture_advance_ms(&f, (uint64_t)rto_ms + 1);
		for (i = 0; i < f.state.out_cnt; i++) {
			tcp_pkt = f.state.out[i];
			if (ii_ntohs(iip_ops_l2_ethertype_be(tcp_pkt, &f.state)) != 0x0800)
				continue;
			if (!PB_TCP_HDR_HAS_SYN(tcp_pkt) || PB_TCP_HDR_HAS_ACK(tcp_pkt) ||
					ii_ntohl(PB_TCP(tcp_pkt)->seq_be) != syn_seq ||
					PB_TCP_PAYLOAD_LEN(tcp_pkt) != 0 ||
					!checksum_valid(tcp_pkt)) {
				*why = "a SYN retransmission did not repeat the original SYN";
				return RESULT_FAIL;
			}
			retransmissions++;
		}
		free_output(&f.state);
	}
	if (f.state.event_dropped) {
		fprintf(stderr, "MUST-22: %u events were dropped from the event log\n",
				f.state.event_dropped);
		*why = "harness error: the event log overflowed, so the close notification cannot be checked";
		return RESULT_FAIL;
	}
	if (!retransmissions) {
		*why = "the SYN was never retransmitted";
		return RESULT_FAIL;
	}
	if (f.conn->state != 0 ||
			!test_event_has_state_transition(&f.state, f.conn,
				II_TCP_STATE_SYN_SENT, II_TCP_STATE_CLOSED) ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) != 1) {
		*why = "the connection attempt was not abandoned with one close notification";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_syn_retry_at_least_three_minutes(const char **why)
{
	struct fixture f;
	uint64_t started_ns;
	uint32_t r2;
	unsigned int timeouts = 0;
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	r2 = f.conn->retrans_r2;
	if (!r2)
		return RESULT_FAIL;
	fixture_prepare_sender(&f);
	f.conn->state = II_TCP_STATE_SYN_SENT;
	test_event_tcp_state_set(&f.state, f.conn, f.conn->state);
	test_api_push(f.ws, f.conn, NULL, 1, 0, 0, 0, 0, NULL,
			0, &f.state);
	fixture_run_timers(&f);
	if (!test_ring_end(f.ws, &f.conn->sent_ring, 0) || output_count_ethertype(&f.state, 0x0800) != 1)
		return RESULT_FAIL;
	started_ns = f.state.now_ns;
	free_output(&f.state);
	test_event_log_clear(&f.state);

	/*
	 * R2 for a SYN may be expressed as a count or as time; RFC 9293 only
	 * requires that it correspond to at least 3 minutes.  Bound the loop
	 * by simulated time rather than by the configured retransmission count.
	 */
	while (f.conn->state == II_TCP_STATE_SYN_SENT &&
			f.state.now_ns - started_ns <= 3600ULL * 1000000000ULL) {
		void *tcp_pkt;
		uint32_t rto_ms;
		if (!test_ring_end(f.ws, &f.conn->sent_ring, 0))
			return RESULT_FAIL;
		rto_ms = f.conn->rto_ms;
		fixture_advance_ms(&f, (uint64_t)rto_ms + 1);
		timeouts++;
		tcp_pkt = output_nth_ethertype(&f.state, 0x0800, 0);
		if (f.conn->state == II_TCP_STATE_SYN_SENT &&
				(!tcp_pkt || !PB_TCP_HDR_HAS_SYN(tcp_pkt) ||
				PB_TCP_HDR_HAS_ACK(tcp_pkt) ||
				PB_TCP_PAYLOAD_LEN(tcp_pkt) != 0 ||
				!checksum_valid(tcp_pkt)))
			return RESULT_FAIL;
		free_output(&f.state);
	}

	if (f.conn->state == 0 &&
			f.state.now_ns - started_ns < 180ULL * 1000000000ULL) {
		fprintf(stderr, "MUST-23: SYN attempt abandoned after %u timeouts and %llu ms\n",
				timeouts, (unsigned long long)
				((f.state.now_ns - started_ns) / 1000000ULL));
		*why = "the SYN attempt was abandoned in less than 3 minutes";
		return RESULT_FAIL;
	}
	return f.conn->state == 0 &&
		f.state.now_ns - started_ns >= 180ULL * 1000000000ULL &&
		test_event_has_state_transition(&f.state, f.conn,
				II_TCP_STATE_SYN_SENT, II_TCP_STATE_CLOSED) &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1
		? RESULT_PASS : RESULT_FAIL;
}


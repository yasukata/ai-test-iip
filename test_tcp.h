/* TCP requirements, API regressions, and malformed-input scenarios.
 * Included by main.c after its shared packet/backend helpers.
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
	fake_clock_advance_ms(&f.state, (uint64_t)initial_rto + 1);
	fixture_run_timers(&f);
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

	fake_clock_advance_ms(&f.state, (uint64_t)initial_rto + 1);
	fixture_run_timers(&f);
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
	fake_clock_advance_ms(&f.state, (uint64_t)first_rto + 1);
	fixture_run_timers(&f);
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
		fake_clock_advance_ms(&f.state, (uint64_t)rto_ms + 1);
		fixture_run_timers(&f);
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
		fake_clock_advance_ms(&f.state, (uint64_t)rto_ms + 1);
		fixture_run_timers(&f);
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
		fake_clock_advance_ms(&f.state, (uint64_t)rto_ms + 1);
		fixture_run_timers(&f);
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

static enum result test_rx_checksum(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	void *pkt;
	pid_t child;
	int ok;
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.corrupt_tcp_checksum = 1;
	pkt = build_tcp_packet(&spec, &f.state);
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child) {
		fixture_deliver(&f, pkt);
		_exit(f.state.payload_chunk_count == 0 && f.conn->seq_next_expected == 0 ? 0 : 1);
	}
	ok = wait_test_child(child, 1000);
	iip_ops_pkt_free(pkt, &f.state);
	return ok ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_arbitrary_segment_options(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	const uint8_t unknown[] = { 253, 4, 0xaa, 0xbb };
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	tcp_packet_add_nop(&spec);
	tcp_packet_add_raw_option(&spec, unknown, sizeof(unknown));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.state.payload_chunk_count == 1 && f.conn->seq_next_expected == 1
		? RESULT_PASS : RESULT_FAIL;
}

static int invalid_tcp_header_length_case(uint8_t data_offset_words)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	void *pkt;
	uint16_t flags;
	uint8_t state_before;
	uint32_t seq_before;
	unsigned int payload_before;

	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &f.state);

	/*
	 * Data Offset is expressed in 32-bit words.  Values below five
	 * describe a TCP header shorter than the mandatory 20-byte base
	 * header.  Larger values may describe a header that extends beyond
	 * the containing IPv4 payload.  Keep every other flag unchanged and
	 * recompute the checksum so rejection is specifically attributable to
	 * the malformed TCP header length rather than a checksum failure.
	 */
	flags = ii_ntohs(PB_TCP(pkt)->flags);
	flags = (uint16_t)((flags & 0x0fffU) |
			((uint16_t)data_offset_words << 12));
	PB_TCP(pkt)->flags = ii_htons(flags);
	update_tcp_checksum(pkt);

	state_before = f.conn->state;
	seq_before = f.conn->seq_next_expected;
	payload_before = f.state.payload_chunk_count;
	fixture_deliver(&f, pkt);

	TEST_CONDITION(f.conn->state == state_before,
			"Data Offset=%u changed state: expected=%u actual=%u",
			data_offset_words, state_before, f.conn->state);
	TEST_CONDITION(f.conn->seq_next_expected == seq_before,
			"Data Offset=%u advanced RCV.NXT: expected=%u actual=%u",
			data_offset_words, seq_before, f.conn->seq_next_expected);
	TEST_CONDITION(f.state.payload_chunk_count == payload_before,
			"Data Offset=%u delivered payload: before=%u after=%u",
			data_offset_words, payload_before,
			f.state.payload_chunk_count);
	TEST_CONDITION(f.state.out_cnt == 0,
			"Data Offset=%u generated %u unexpected output packet(s)",
			data_offset_words, f.state.out_cnt);
	TEST_CONDITION(test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_PAYLOAD) == 0,
			"Data Offset=%u invoked the payload callback", data_offset_words);
	return 1;
}

static int invalid_tcp_header_length_scenario(void)
{
	static const uint8_t invalid_offsets[] = {
		0, 1, 2, 3, 4, /* shorter than the 20-byte TCP base header */
		6, 15,         /* longer than this packet's TCP segment */
	};
	unsigned int i;

	for (i = 0; i < ARRAY_LENGTH(invalid_offsets); i++)
		if (!invalid_tcp_header_length_case(invalid_offsets[i]))
			return 0;
	return 1;
}

static enum result test_invalid_tcp_header_length(const char **why)
{
	pid_t child;

	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(invalid_tcp_header_length_scenario() ? 0 : 1);
	if (!wait_test_child(child, 2000)) {
		*why = "invalid TCP Data Offset was accepted or caused a crash/hang";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int malformed_input_normal_controls(void)
{
	struct fixture checksum, full_length, base_header, extended_header;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	const uint8_t options[] = { 1, 1, 0, 0 };
	void *pkt;

	/* Valid checksums must be accepted before corrupt-checksum rejection is trusted. */
	if (!fixture_init(&checksum))
		return 0;
	fixture_incoming_spec(&checksum, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &checksum.state);
	if (!ip4_checksum_valid(pkt) || !checksum_valid(pkt))
		return 0;
	fixture_deliver(&checksum, pkt);
	if (checksum.state.payload_chunk_count != 1 ||
			checksum.conn->seq_next_expected != 1)
		return 0;

	/* A physically complete IPv4/TCP packet must pass the truncation controls. */
	if (!fixture_init(&full_length))
		return 0;
	fixture_incoming_spec(&full_length, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &full_length.state);
	if (iip_ops_pkt_get_len(pkt, &full_length.state) !=
			14 + sizeof(struct iip_ip4_hdr) +
			sizeof(struct iip_tcp_hdr) + sizeof(payload))
		return 0;
	fixture_deliver(&full_length, pkt);
	if (full_length.state.payload_chunk_count != 1)
		return 0;

	/* Data Offset 5 is the valid minimum TCP header length. */
	if (!fixture_init(&base_header))
		return 0;
	fixture_incoming_spec(&base_header, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &base_header.state);
	if (PB_TCP_HDR_LEN(pkt) != 5)
		return 0;
	fixture_deliver(&base_header, pkt);
	if (base_header.state.payload_chunk_count != 1)
		return 0;

	/* Data Offset 6 is valid when four option bytes are physically present. */
	if (!fixture_init(&extended_header))
		return 0;
	fixture_incoming_spec(&extended_header, &spec, 0, payload, sizeof(payload));
	tcp_packet_add_raw_option(&spec, options, sizeof(options));
	pkt = build_tcp_packet(&spec, &extended_header.state);
	if (PB_TCP_HDR_LEN(pkt) != 6)
		return 0;
	fixture_deliver(&extended_header, pkt);
	return extended_header.state.payload_chunk_count == 1 &&
		extended_header.conn->seq_next_expected == 1;
}

static int malformed_checksum_cases(void)
{
	unsigned int i;
	for (i = 0; i < 2; i++) {
		struct fixture f;
		struct tcp_packet_spec spec;
		const uint8_t payload[] = { 0x5a };
		void *pkt;
		if (!fixture_init(&f))
			return 0;
		fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
		pkt = build_tcp_packet(&spec, &f.state);
		if (i == 0)
			PB_IP4(pkt)->csum_be ^= ii_htons(1);
		else
			PB_TCP(pkt)->csum_be ^= ii_htons(1);
		fixture_deliver(&f, pkt);
		if (f.state.payload_chunk_count != 0 || f.conn->seq_next_expected != 0 ||
			f.state.out_cnt != 0)
			return 0;
	}
	return 1;
}

static int truncated_packet_case(uint16_t packet_len)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	void *pkt;
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &f.state);
	assert(packet_len < iip_ops_pkt_get_len(pkt, &f.state));
	iip_ops_pkt_set_len(pkt, packet_len, &f.state);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 && f.conn->seq_next_expected == 0 &&
		f.state.out_cnt == 0;
}

static int truncated_packet_cases(void)
{
	static const uint16_t lengths[] = {
		14,      /* Ethernet frame without any IPv4 header bytes. */
		14 + 19, /* IPv4 base header truncated by one byte. */
		14 + 20, /* Complete IPv4 header, no TCP bytes. */
		14 + 20 + 19, /* TCP base header truncated by one byte. */
		14 + 20 + 20, /* Payload declared by IPv4 but physically absent. */
	};
	unsigned int i;
	for (i = 0; i < ARRAY_LENGTH(lengths); i++)
		if (!truncated_packet_case(lengths[i]))
			return 0;
	return 1;
}

static int invalid_flag_combination_case(uint8_t tcp_flags)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	uint8_t state_before;
	uint32_t seq_before;
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags = tcp_flags;
	state_before = f.conn->state;
	seq_before = f.conn->seq_next_expected;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.conn->state == state_before,
			"flags=0x%02x changed state: expected=%u actual=%u",
			tcp_flags, state_before, f.conn->state);
	TEST_CONDITION(f.conn->seq_next_expected == seq_before,
			"flags=0x%02x advanced RCV.NXT: expected=%u actual=%u",
			tcp_flags, seq_before, f.conn->seq_next_expected);
	TEST_CONDITION(f.state.payload_chunk_count == 0,
			"flags=0x%02x delivered %u payload chunk(s)",
			tcp_flags, f.state.payload_chunk_count);
	return 1;
}

static int reset_flag_combination_case(uint8_t tcp_flags)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	uint8_t state_before;
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags = tcp_flags;
	state_before = f.conn->state;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.state.payload_chunk_count == 0,
			"RST flags=0x%02x delivered %u payload chunk(s)",
			tcp_flags, f.state.payload_chunk_count);
	TEST_CONDITION(test_event_has_state_transition(&f.state, f.conn,
				state_before, II_TCP_STATE_CLOSED),
			"RST flags=0x%02x did not transition state %u -> CLOSED",
			tcp_flags, state_before);
	TEST_CONDITION(test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1,
			"RST flags=0x%02x produced %u closed callback(s); expected 1",
			tcp_flags, test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED));
	return 1;
}

static int invalid_flag_combination_cases(void)
{
	static const uint8_t invalid_combinations[] = {
		TEST_TCP_SYN | TEST_TCP_FIN,
	};
	static const uint8_t reset_combinations[] = {
		TEST_TCP_SYN | TEST_TCP_RST,
		TEST_TCP_FIN | TEST_TCP_RST,
		TEST_TCP_SYN | TEST_TCP_FIN | TEST_TCP_RST,
	};
	unsigned int i;
	for (i = 0; i < ARRAY_LENGTH(invalid_combinations); i++)
		if (!invalid_flag_combination_case(invalid_combinations[i]))
			return 0;
	/*
	 * RFC 9293 Section 3.10.7.4 checks RST before SYN and FIN in
	 * synchronized states.  An acceptable RST therefore resets the
	 * connection even when either of those flags is also present.
	 */
	for (i = 0; i < ARRAY_LENGTH(reset_combinations); i++)
		if (!reset_flag_combination_case(reset_combinations[i]))
			return 0;
	return 1;
}

static int mss_boundary_case(uint16_t advertised_mss)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_pb *p;
	void *payload;
	uint32_t expected_seq;
	unsigned int total = 0;
	const uint16_t payload_len = advertised_mss == 1 ? 4 : 1600;

	if (!fixture_init(&f))
		return 0;
	f.conn->state = II_TCP_STATE_SYN_SENT;
	/* Exercise small MSS without Timestamp option overhead. */
	f.conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	spec.ack_seq = f.conn->seq + 1;
	tcp_packet_add_mss(&spec, advertised_mss);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.payload_chunk_count != 0)
		return 0;
	/* Zero is a robustness case: rejection or a usable fallback is allowed.
	 * RFC 9293 does not prescribe retaining the configured initial MSS. */
	/* MSS 0 and MSS 1 are robustness cases; refusing such a connection
	 * is an acceptable defense, but an established connection must honor
	 * the advertised MSS (MUST-16). */
	if (advertised_mss <= 1 && f.conn->state != II_TCP_STATE_ESTABLISHED)
		return 1;
	if (f.conn->state != II_TCP_STATE_ESTABLISHED || !f.conn->mss)
		return 0;

	/* Check wire behavior, without prescribing how peer MSS is stored. */
	expected_seq = f.conn->seq;
	payload = iip_ops_pkt_alloc(&f.state);
	if (!payload)
		return 0;
	memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, payload_len);
	iip_ops_pkt_set_len(payload, payload_len, &f.state);
	test_api_push(f.ws, f.conn, payload, 0, 1, 0, 0, 0,
			NULL, 0, &f.state);
	free_output(&f.state);
	p = test_ring_end(f.ws, &f.conn->tx_ring, 0);
	if (!p || ii_tcp_xmit_queued_data_one(f.ws,
			test_conn_id(f.ws, f.conn), (uint32_t)(p - f.ws->pbs.array),
			0, p->tcp.payload_len, &f.state) != IIP_ERR_OK)
		return 0;
	for (unsigned int i = 0; i < f.state.out_cnt; i++) {
		void *pkt = f.state.out[i];
		uint16_t len = PB_TCP_PAYLOAD_LEN(pkt);
		if (!len || (advertised_mss && len > advertised_mss) ||
				ii_ntohs(PB_IP4(pkt)->len_be) > f.conn->path_mtu ||
				ii_ntohl(PB_TCP(pkt)->seq_be) != expected_seq ||
				!ip4_checksum_valid(pkt) || !checksum_valid(pkt))
			return 0;
		for (uint16_t j = 0; j < len; j++)
			if (PB_TCP_PAYLOAD(pkt)[j] != 0x5a)
				return 0;
		expected_seq += len;
		total += len;
	}
	return total == payload_len;
}

static int payload_length_boundary_cases(void)
{
	struct fixture empty, maximum;
	struct tcp_packet_spec spec;
	const struct test_event *payload_event;
	uint8_t *payload;
	const uint16_t maximum_payload =
		2048 - 8 * sizeof(long) - 14 - sizeof(struct iip_ip4_hdr) -
		sizeof(struct iip_tcp_hdr);
	if (!fixture_init(&empty) || !fixture_init(&maximum))
		return 0;
	fixture_incoming_spec(&empty, &spec, 0, NULL, 0);
	fixture_deliver(&empty, build_tcp_packet(&spec, &empty.state));
	if (empty.state.payload_chunk_count != 0 || empty.conn->seq_next_expected != 0)
		return 0;
	payload = malloc(maximum_payload);
	if (!payload)
		return 0;
	{
		uint16_t i;
		for (i = 0; i < maximum_payload; i++)
			payload[i] = (uint8_t)i;
	}
	fixture_incoming_spec(&maximum, &spec, 0, payload, maximum_payload);
	fixture_deliver(&maximum, build_tcp_packet(&spec, &maximum.state));
	free(payload);
	payload_event = test_event_nth(&maximum.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 0);
	return maximum.state.payload_chunk_count == 1 && payload_event &&
		payload_event->value[0] == maximum_payload &&
		maximum.state.payload_byte_count == maximum_payload &&
		maximum.conn->seq_next_expected == maximum_payload;
}

static int additional_malformed_boundary_scenario(void)
{
	int ok = 1;

	/* Positive controls prevent an always-drop implementation from passing. */
	TEST_ACCUMULATE(ok, malformed_input_normal_controls(),
			"positive controls failed: valid checksum, complete packet, or valid Data Offset was rejected");

	/* Do not short-circuit: exercise every malformed-input family. */
	TEST_ACCUMULATE(ok, malformed_checksum_cases(),
			"invalid IPv4 or TCP checksum changed connection state, delivered payload, or generated output");
	TEST_ACCUMULATE(ok, truncated_packet_cases(),
			"a physically truncated IPv4/TCP packet was not silently discarded");
	TEST_ACCUMULATE(ok, invalid_flag_combination_cases(),
			"SYN/FIN/RST flag precedence or reset notification was incorrect");
	TEST_ACCUMULATE(ok, mss_boundary_case(0),
			"MSS=0 was neither safely rejected nor handled with a usable fallback");
	TEST_ACCUMULATE(ok, mss_boundary_case(1),
			"MSS=1 handshake or one-octet payload segmentation failed");
	TEST_ACCUMULATE(ok,
			mss_boundary_case(UINT16_MAX),
			"MSS=65535 handshake or path-MTU-limited transmission failed");
	TEST_ACCUMULATE(ok, payload_length_boundary_cases(),
			"zero-length or maximum-length payload boundary handling failed");
	return ok;
}

static enum result test_additional_malformed_boundaries(const char **why)
{
	pid_t child;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(additional_malformed_boundary_scenario() ? 0 : 1);
	if (!wait_test_child(child, 5000)) {
		*why = "checksum, truncation, flag, MSS, or payload boundary test failed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

struct fuzz_config {
	uint64_t seed;
	unsigned int cases;
	const char *failure_prefix;
};

static uint64_t fuzz_random(uint64_t *state)
{
	uint64_t x = *state;

	/* xorshift64*: compact, deterministic, and identical across platforms. */
	if (!x)
		x = 0x9e3779b97f4a7c15ULL;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 2685821657736338717ULL;
}

static struct fuzz_config fuzz_config_get(void)
{
	struct fuzz_config config = {
		0x4959502d46555a5aULL, /* "IYP-FUZZ" default seed. */
		64,
		"iip-fuzz-failure",
	};
	const char *value;
	char *end;
	unsigned long long parsed;

	value = getenv("IIP_FUZZ_SEED");
	if (value && *value) {
		parsed = strtoull(value, &end, 0);
		if (*end == '\0')
			config.seed = (uint64_t)parsed;
	}
	value = getenv("IIP_FUZZ_CASES");
	if (value && *value) {
		parsed = strtoull(value, &end, 0);
		if (*end == '\0' && parsed > 0 && parsed <= 100000)
			config.cases = (unsigned int)parsed;
	}
	value = getenv("IIP_FUZZ_FAILURE_PREFIX");
	if (value && *value)
		config.failure_prefix = value;
	return config;
}

static void fuzz_mutate_packet(void *pkt, void *opaque, uint64_t *random_state)
{
	uint8_t *data = iip_ops_pkt_get_data(pkt, opaque);
	uint16_t len = iip_ops_pkt_get_len(pkt, opaque);
	unsigned int mutations = 1U + (unsigned int)(fuzz_random(random_state) % 8U);
	unsigned int i;

	for (i = 0; i < mutations && len; i++) {
		uint64_t random = fuzz_random(random_state);
		uint16_t offset = (uint16_t)(random % len);
		uint8_t operation = (uint8_t)((random >> 16) % 4U);
		if (operation == 0)
			data[offset] ^= (uint8_t)(1U << ((random >> 24) & 7U));
		else if (operation == 1)
			data[offset] = (uint8_t)(random >> 32);
		else if (operation == 2)
			data[offset] = 0;
		else
			data[offset] = 0xff;
	}

	/* Occasionally truncate at any byte boundary, including empty L3/L4. */
	if ((fuzz_random(random_state) & 3U) == 0 && len)
		iip_ops_pkt_set_len(pkt,
			(uint16_t)(fuzz_random(random_state) % len), opaque);
}

static int fuzz_repair_ip4_tcp_checksums(void *pkt, void *opaque)
{
	uint16_t frame_len = iip_ops_pkt_get_len(pkt, opaque);
	uint16_t l2_len = iip_ops_l2_hdr_len(pkt, opaque);
	struct iip_ip4_hdr *ip4;
	uint16_t ip_header_len;
	uint16_t ip_total_len;

	if (frame_len < l2_len + sizeof(*ip4))
		return 0;
	ip4 = (struct iip_ip4_hdr *)((uint8_t *)iip_ops_pkt_get_data(pkt,
				opaque) + l2_len);
	if ((ip4->vl >> 4) != 4)
		return 0;
	ip_header_len = (uint16_t)(ip4->vl & 0x0f) * 4;
	ip_total_len = ii_ntohs(ip4->len_be);
	if (ip_header_len < sizeof(*ip4) || ip_header_len > 60 ||
			ip_total_len < ip_header_len + sizeof(struct iip_tcp_hdr) ||
			ip_total_len > frame_len - l2_len || ip4->proto != 6)
		return 0;
	update_ip4_checksum(pkt);
	update_tcp_checksum(pkt);
	return 1;
}

static int fuzz_save_failure(const struct fuzz_config *config,
		uint64_t case_seed, unsigned int case_index, void *pkt, void *opaque)
{
	char packet_path[512], metadata_path[512];
	FILE *file;
	uint8_t *data = iip_ops_pkt_get_data(pkt, opaque);
	uint16_t len = iip_ops_pkt_get_len(pkt, opaque);

	if (snprintf(packet_path, sizeof(packet_path), "%s-%016llx-%u.bin",
			config->failure_prefix, (unsigned long long)case_seed,
			case_index) >= (int)sizeof(packet_path) ||
			snprintf(metadata_path, sizeof(metadata_path), "%s-%016llx-%u.txt",
			config->failure_prefix, (unsigned long long)case_seed,
			case_index) >= (int)sizeof(metadata_path))
		return 0;
	file = fopen(packet_path, "wb");
	if (!file)
		return 0;
	if (fwrite(data, 1, len, file) != len) {
		fclose(file);
		return 0;
	}
	fclose(file);
	file = fopen(metadata_path, "w");
	if (!file)
		return 0;
	fprintf(file, "seed=0x%016llx\ncase=%u\nlength=%u\npacket=%s\n",
		(unsigned long long)case_seed, case_index, len, packet_path);
	fclose(file);
	fprintf(stderr,
		"fuzz failure: seed=0x%016llx case=%u packet=%s metadata=%s\n",
		(unsigned long long)case_seed, case_index, packet_path, metadata_path);
	return 1;
}

static int reproducible_packet_fuzz_scenario(void)
{
	struct fuzz_config config = fuzz_config_get();
	uint64_t suite_state = config.seed;
	unsigned int i;

	for (i = 0; i < config.cases; i++) {
		struct fixture f;
		struct tcp_packet_spec spec;
		uint8_t payload[32];
		uint64_t case_seed = fuzz_random(&suite_state);
		uint64_t case_state = case_seed;
		void *pkt;
		pid_t child;
		unsigned int j;

		if (!fixture_init(&f))
			return 0;
		for (j = 0; j < sizeof(payload); j++)
			payload[j] = (uint8_t)j;
		fixture_incoming_spec(&f, &spec, 0, payload,
			(uint16_t)(fuzz_random(&case_state) % (sizeof(payload) + 1U)));
		pkt = build_tcp_packet(&spec, &f.state);
		fuzz_mutate_packet(pkt, &f.state, &case_state);
		/*
		 * Preserve malformed-checksum coverage, but repair checksums for
		 * alternating structurally valid cases so mutations can reach the
		 * TCP option parser and state machine.
		 */
		if (i & 1U)
			(void)fuzz_repair_ip4_tcp_checksums(pkt, &f.state);

		fflush(NULL);
		child = fork();
		assert(child >= 0);
		if (!child) {
			f.state.accept_arbitrary_payload = 1;
			fixture_deliver(&f, pkt);
			_exit(0);
		}
		if (!wait_test_child(child, 1000)) {
			fuzz_save_failure(&config, case_seed, i, pkt, &f.state);
			iip_ops_pkt_free(pkt, &f.state);
			return 0;
		}
		iip_ops_pkt_free(pkt, &f.state);
	}
	return 1;
}

static enum result test_reproducible_packet_fuzz(const char **why)
{
	struct fuzz_config config = fuzz_config_get();

	if (!reproducible_packet_fuzz_scenario()) {
		*why = "reproducible packet fuzzing found a crash, assertion, or hang";
		return RESULT_FAIL;
	}
	printf("fuzz: seed=0x%016llx cases=%u\n",
		(unsigned long long)config.seed, config.cases);
	return RESULT_PASS;
}

static enum result test_invalid_option_length(const char **why)
{
	(void)legacy_test_main();
	if (!legacy_malformed_tests_passed) {
		*why = "legacy malformed-option test failed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

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
	f.conn->state = II_TCP_STATE_FIN_WAIT1;
	test_event_tcp_state_set(&f.state, f.conn, f.conn->state);
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_FIN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->state != II_TCP_STATE_CLOSING)
		return 0;
	free_output(&f.state);
	fixture_incoming_spec(&f, &spec, 1, NULL, 0);
	spec.tcp_flags = TEST_TCP_ACK;
	spec.ack_seq = f.conn->seq;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.conn->state == II_TCP_STATE_TIME_WAIT;
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
	return f.conn->seq_next_expected == 2U && f.state.payload_chunk_count == 1 &&
		f.state.payload_byte_count == sizeof(payload) &&
		payload_event && payload_event->value[0] == sizeof(payload);
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
	syn_sent_ack.conn->state = II_TCP_STATE_SYN_SENT;
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

static enum result test_multiple_listens_same_port(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct test_listener *listener_a, *listener_b;
	struct test_listener listener_a_before;
	struct ii_tcp_conn *child_a, *child_b;
	const struct test_event *accept_event;
	const uint16_t local_port_be = ii_htons(10000);
	const uint16_t peer_a_port_be = ii_htons(22001);
	const uint16_t peer_b_port_be = ii_htons(22002);

	if (!fixture_init(&f))
		return RESULT_FAIL;

	/* A connection using the same local port is already in SYN-SENT. */
	f.conn->state = II_TCP_STATE_SYN_SENT;
	test_event_tcp_state_set(&f.state, f.conn, f.conn->state);
	listener_a = test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			local_port_be, ii_htonl(f.conn->dst_ip[0]), peer_a_port_be,
			(void *)(uintptr_t)1);
	if (!listener_a || f.conn->state != II_TCP_STATE_SYN_SENT) {
		*why = "a connection in SYN-SENT prevented a passive OPEN on the same port";
		return RESULT_FAIL;
	}
	listener_a_before = *listener_a;
	test_event_log_clear(&f.state);

	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.src_port_be = peer_a_port_be;
	spec.dst_port_be = local_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	child_a = fixture_find_peer_port(&f, peer_a_port_be);
	accept_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPT, 0);
	if (!child_a || child_a == f.conn ||
			child_a->state != II_TCP_STATE_SYN_RECVD ||
			f.conn->state != II_TCP_STATE_SYN_SENT ||
			!accept_event || accept_event->value[0] != 1 ||
			!output_has_syn_ack(&f.state)) {
		*why = "the first LISTEN did not coexist with the SYN-SENT connection";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	test_event_log_clear(&f.state);

	/* A second passive OPEN on the same local port must coexist with the
	 * first listener and its child connection in SYN-RECEIVED. */
	listener_b = test_tcp_listen(&f.state, ii_htonl(f.conn->src_ip[0]),
			local_port_be, ii_htonl(f.conn->dst_ip[0]), peer_b_port_be,
			(void *)(uintptr_t)2);
	if (!listener_b || listener_b == listener_a ||
			memcmp(listener_a, &listener_a_before,
				sizeof(*listener_a)) != 0 ||
			child_a->state != II_TCP_STATE_SYN_RECVD) {
		*why = "a SYN-RECEIVED connection prevented another LISTEN on the same port";
		return RESULT_FAIL;
	}

	fixture_incoming_spec(&f, &spec, 200, NULL, 0);
	spec.src_port_be = peer_b_port_be;
	spec.dst_port_be = local_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	child_b = fixture_find_peer_port(&f, peer_b_port_be);
	accept_event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_ACCEPT, 0);
	if (!child_b || child_b == child_a || child_b == f.conn ||
			child_b->state != II_TCP_STATE_SYN_RECVD ||
			child_a->state != II_TCP_STATE_SYN_RECVD ||
			f.conn->state != II_TCP_STATE_SYN_SENT ||
			!accept_event || accept_event->value[0] != 2 ||
			!output_has_syn_ack(&f.state) ||
			memcmp(listener_a, &listener_a_before,
				sizeof(*listener_a)) != 0) {
		*why = "multiple LISTENs on one local port interfered with each other";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}

static enum result test_optional_local_address(const char **why)
{
	struct fixture specified, wildcard, active_specified, active_unspecified;
	struct tcp_packet_spec spec;
	struct ii_tcp_conn *child;
	void *input[1];
	const uint32_t alternate_local_ip4_be = ii_htonl(0xc0000263U);
	const uint16_t listen_port_be = ii_htons(10000);
	const uint16_t active_port_be = ii_htons(11000);
	const uint16_t peer_port_be = ii_htons(80);

	/* A specified passive local address only matches SYNs for that address. */
	if (!fixture_init(&specified) ||
			!test_tcp_listen(&specified.state, ii_htonl(specified.conn->src_ip[0]),
				listen_port_be, 0, 0, NULL))
		return RESULT_FAIL;
	fixture_incoming_spec(&specified, &spec, 100, NULL, 0);
	spec.src_port_be = ii_htons(23001);
	spec.dst_ip_be = alternate_local_ip4_be;
	spec.dst_port_be = listen_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	input[0] = build_tcp_packet(&spec, &specified.state);
	deliver(specified.ws, specified.local_mac, alternate_local_ip4_be,
			input, 1, &specified.state);
	if (output_has_syn_ack(&specified.state))
		return RESULT_FAIL;
	free_output(&specified.state);

	test_event_log_clear(&specified.state);
	fixture_incoming_spec(&specified, &spec, 200, NULL, 0);
	spec.src_port_be = ii_htons(23001);
	spec.dst_port_be = listen_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	fixture_deliver(&specified, build_tcp_packet(&spec, &specified.state));
	child = fixture_find_peer_port(&specified, spec.src_port_be);
	if (!child || ii_htonl(child->src_ip[0]) != ii_htonl(specified.conn->src_ip[0]) ||
			!output_has_syn_ack(&specified.state) ||
			PB_IP4(specified.state.out[0])->src_be !=
				ii_htonl(specified.conn->src_ip[0])) {
		*why = "a specified passive local address was not honored";
		return RESULT_FAIL;
	}
	free_output(&specified.state);

	/* An unspecified passive address matches any local address and binds
	 * the child connection to the destination address of the SYN. */
	if (!fixture_init(&wildcard) ||
			!test_tcp_listen(&wildcard.state, 0, listen_port_be, 0, 0, NULL))
		return RESULT_FAIL;
	fixture_incoming_spec(&wildcard, &spec, 300, NULL, 0);
	spec.src_port_be = ii_htons(23002);
	spec.dst_ip_be = alternate_local_ip4_be;
	spec.dst_port_be = listen_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	input[0] = build_tcp_packet(&spec, &wildcard.state);
	deliver(wildcard.ws, wildcard.local_mac, alternate_local_ip4_be,
			input, 1, &wildcard.state);
	child = fixture_find_peer_port(&wildcard, spec.src_port_be);
	if (!child || ii_htonl(child->src_ip[0]) != alternate_local_ip4_be ||
			!output_has_syn_ack(&wildcard.state) ||
			PB_IP4(wildcard.state.out[0])->src_be != alternate_local_ip4_be) {
		*why = "an unspecified passive local address did not bind to the SYN destination";
		return RESULT_FAIL;
	}
	free_output(&wildcard.state);

	/* A specified active local address is passed through without asking
	 * the application-side source-address selector. */
	if (!fixture_init(&active_specified) ||
			test_tcp_active_open(active_specified.ws,
				active_specified.local_mac,
				&(uint32_t){ ii_htonl(active_specified.conn->src_ip[0]) }, active_port_be,
				active_specified.peer_mac,
				ii_htonl(active_specified.conn->dst_ip[0]), peer_port_be,
				&active_specified.state) == 0xffff)
		return RESULT_FAIL;
	fixture_run_timers(&active_specified);
	if (active_specified.state.source_address_query_count != 0 ||
			active_specified.state.out_cnt != 1 ||
			!PB_TCP_HDR_HAS_SYN(active_specified.state.out[0]) ||
			PB_IP4(active_specified.state.out[0])->src_be !=
				ii_htonl(active_specified.conn->src_ip[0])) {
		*why = "a specified active local address was not used for the SYN";
		return RESULT_FAIL;
	}
	free_output(&active_specified.state);

	/* With no active local address, the wrapper selects one before calling
	 * the existing TCP connect API. */
	if (!fixture_init(&active_unspecified))
		return RESULT_FAIL;
	active_unspecified.state.source_address_available = 1;
	active_unspecified.state.selected_source_ip4_be = alternate_local_ip4_be;
	if (test_tcp_active_open(active_unspecified.ws,
			active_unspecified.local_mac, NULL, active_port_be,
			active_unspecified.peer_mac,
			ii_htonl(active_unspecified.conn->dst_ip[0]), peer_port_be,
			&active_unspecified.state) == 0xffff)
		return RESULT_FAIL;
	fixture_run_timers(&active_unspecified);
	if (active_unspecified.state.source_address_query_count != 1 ||
			active_unspecified.state.source_address_query_peer_ip4_be !=
				ii_htonl(active_unspecified.conn->dst_ip[0]) ||
			active_unspecified.state.out_cnt != 1 ||
			!PB_TCP_HDR_HAS_SYN(active_unspecified.state.out[0]) ||
			PB_IP4(active_unspecified.state.out[0])->src_be !=
				alternate_local_ip4_be) {
		*why = "an unspecified active local address was not selected before SYN";
		return RESULT_FAIL;
	}
	free_output(&active_unspecified.state);
	return RESULT_PASS;
}

static enum result test_source_address_query(const char **why)
{
	struct fixture selected, unavailable;
	struct ii_tcp_conn *conn;
	const uint32_t selected_ip4_be = ii_htonl(0xc0000263U);
	const uint16_t local_port_be = ii_htons(12000);
	const uint16_t peer_port_be = ii_htons(80);

	/* Without an application-supplied local address, active OPEN asks the
	 * IP-side selector using the connection's destination address. */
	if (!fixture_init(&selected))
		return RESULT_FAIL;
	selected.state.source_address_available = 1;
	selected.state.selected_source_ip4_be = selected_ip4_be;
	if (test_tcp_active_open(selected.ws, selected.local_mac, NULL,
			local_port_be, selected.peer_mac, ii_htonl(selected.conn->dst_ip[0]),
			peer_port_be, &selected.state) == 0xffff)
		return RESULT_FAIL;
	conn = fixture_find_peer_port(&selected, peer_port_be);
	fixture_run_timers(&selected);
	if (selected.state.source_address_query_count != 1 ||
			selected.state.source_address_query_peer_ip4_be !=
				ii_htonl(selected.conn->dst_ip[0]) ||
			!conn || conn == selected.conn ||
			ii_htonl(conn->src_ip[0]) != selected_ip4_be ||
			selected.state.out_cnt != 1 ||
			!PB_TCP_HDR_HAS_SYN(selected.state.out[0]) ||
			PB_IP4(selected.state.out[0])->src_be != selected_ip4_be) {
		*why = "active OPEN did not use the IP-selected source address";
		return RESULT_FAIL;
	}
	free_output(&selected.state);

	/* If IP cannot select a source address, no connection or SYN is made. */
	if (!fixture_init(&unavailable))
		return RESULT_FAIL;
	if (test_tcp_active_open(unavailable.ws, unavailable.local_mac, NULL,
			local_port_be, unavailable.peer_mac,
			ii_htonl(unavailable.conn->dst_ip[0]), peer_port_be,
			&unavailable.state) != 0xffff ||
			unavailable.state.source_address_query_count != 1 ||
			unavailable.state.source_address_query_peer_ip4_be !=
				ii_htonl(unavailable.conn->dst_ip[0]) ||
			fixture_find_peer_port(&unavailable, peer_port_be) != NULL ||
			unavailable.state.out_cnt != 0) {
		*why = "active OPEN continued after source-address selection failed";
		return RESULT_FAIL;
	}

	return RESULT_PASS;
}

static enum result test_connection_local_address_fallback(const char **why)
{
	struct fixture f;
	struct ii_tcp_conn *conn;
	const uint32_t configured_ip4_be = ii_htonl(0xc000027bU);
	const uint32_t selector_ip4_be = ii_htonl(0xc000027cU);
	const uint16_t local_port_be = ii_htons(13000);
	const uint16_t peer_port_be = ii_htons(81);

	if (!fixture_init(&f))
		return RESULT_FAIL;
	/* Configure a different selector result so an unintended query/use is
	 * visible in both the counter and the emitted SYN. */
	f.state.source_address_available = 1;
	f.state.selected_source_ip4_be = selector_ip4_be;
	if (test_tcp_active_open(f.ws, f.local_mac, &configured_ip4_be,
			local_port_be, f.peer_mac, ii_htonl(f.conn->dst_ip[0]),
			peer_port_be, &f.state) == 0xffff)
		return RESULT_FAIL;
	conn = fixture_find_peer_port(&f, peer_port_be);
	fixture_run_timers(&f);
	if (f.state.source_address_query_count != 0 ||
			!conn || conn == f.conn ||
			ii_htonl(conn->src_ip[0]) != configured_ip4_be ||
			ii_htons(conn->src_port) != local_port_be ||
			f.state.out_cnt != 1 ||
			!PB_TCP_HDR_HAS_SYN(f.state.out[0]) ||
			PB_IP4(f.state.out[0])->src_be != configured_ip4_be ||
			PB_IP4(f.state.out[0])->src_be == selector_ip4_be) {
		*why = "active OPEN did not use the connection's local address";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	return RESULT_PASS;
}

static enum result test_abort_callback_observed(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return test_event_has_state_transition(&f.state, f.conn,
			II_TCP_STATE_ESTABLISHED, II_TCP_STATE_CLOSED) &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1
		? RESULT_PASS : RESULT_FAIL;
}

static int time_wait_scenario(void)
{
	struct fixture f;
	if (!fixture_init(&f))
		return 0;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	f.conn->state = II_TCP_STATE_TIME_WAIT;
	f.conn->time_wait_ts_ms = 1000;
	fixture_run_timers(&f);
	fake_clock_advance_ms(&f.state, IIP_CONF_TCP_MSL_SEC * 2000ULL - 1);
	fixture_run_timers(&f);
	if (f.conn->state != II_TCP_STATE_TIME_WAIT)
		return 0;
	fake_clock_advance_ms(&f.state, 1);
	fixture_run_timers(&f);
	if (f.conn->state == II_TCP_STATE_CLOSED) return 1;
	/* iip slow timer granularity: allow its next invocation after expiry. */
	fake_clock_advance_ms(&f.state, 1000);
	fixture_run_timers(&f);
	return f.conn->state == II_TCP_STATE_CLOSED;
}

static enum result test_time_wait_2msl(const char **why)
{
	pid_t child;
	(void)why;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(time_wait_scenario() ? 0 : 1);
	return wait_test_child(child, 1000) ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_keepalive_default_off(const char **why)
{
	struct fixture f;
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	fixture_run_timers(&f);
	test_event_log_clear(&f.state);
	fake_clock_advance_sec(&f.state, 2 * 60 * 60 + 1);
	fixture_run_timers(&f);
	return test_event_count(&f.state, TEST_EVENT_TIMER, 0) > 0 &&
		test_event_count(&f.state, TEST_EVENT_TX_PACKET, 0) == 0
		? RESULT_PASS : RESULT_FAIL;
}

static int fixture_has_keepalive_probe(struct fixture *f,
		uint32_t expected_seq)
{
	void *pkt;
	if (f->state.out_cnt != 1)
		return 0;
	pkt = f->state.out[0];
	return PB_TCP_HDR_HAS_ACK(pkt) && !PB_TCP_HDR_HAS_SYN(pkt) &&
		!PB_TCP_HDR_HAS_FIN(pkt) && !PB_TCP_HDR_HAS_RST(pkt) &&
		PB_TCP_PAYLOAD_LEN(pkt) <= 1 && checksum_valid(pkt) &&
		ii_ntohl(PB_TCP(pkt)->seq_be) == expected_seq;
}

static enum result test_keepalive_per_connection(const char **why)
{
	struct fixture enabled, disabled;
	uint32_t expected_seq;
	if (!fixture_init(&enabled) || !fixture_init(&disabled))
		return RESULT_FAIL;
	fake_clock_set_ns(&enabled.state, 1000000000ULL);
	fake_clock_set_ns(&disabled.state, 1000000000ULL);
	expected_seq = enabled.conn->seq - 1U;
	test_set_keepalive(enabled.ws, enabled.conn, 1000U,
			&enabled.state);
	fake_clock_advance_ms(&enabled.state, 1001);
	fake_clock_advance_ms(&disabled.state, 1001);
	fixture_run_timers(&enabled);
	fixture_run_timers(&disabled);
	if (!fixture_has_keepalive_probe(&enabled, expected_seq) ||
			disabled.state.out_cnt != 0) {
		*why = "keep-alive could not be enabled per connection";
		return RESULT_FAIL;
	}
	free_output(&enabled.state);
	test_set_keepalive(enabled.ws, enabled.conn, 0,
			&enabled.state);
	fake_clock_advance_ms(&enabled.state, 2000);
	fixture_run_timers(&enabled);
	if (enabled.state.out_cnt != 0) {
		*why = "keep-alive could not be disabled per connection";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/* A keep-alive carries SEG.SEQ = SND.UNA - 1 (RFC 9293 Section 3.8.4). */
static int output_has_keepalive(struct fixture *f)
{
	unsigned int i;
	for (i = 0; i < f->state.out_cnt; i++)
		if (ii_ntohl(PB_TCP(f->state.out[i])->seq_be) ==
				f->conn->acked_seq - 1U)
			return 1;
	return 0;
}

static enum result test_keepalive_idle_condition(const char **why)
{
	struct fixture outstanding, active;
	struct tcp_packet_spec spec;
	uint32_t expected_seq;
	if (!fixture_init(&outstanding) || !fixture_init(&active))
		return RESULT_FAIL;
	fixture_prepare_sender(&outstanding);
	test_set_keepalive(outstanding.ws, outstanding.conn, 1000U,
			&outstanding.state);
	if (!fixture_send_data(&outstanding, 1))
		return RESULT_FAIL;
	free_output(&outstanding.state);
	fake_clock_advance_ms(&outstanding.state, 1001);
	fixture_run_timers(&outstanding);
	/* An RTO retransmission of the outstanding octet is expected here;
	 * only a keep-alive (SEG.SEQ = SND.UNA - 1) violates the idle rule. */
	if (output_has_keepalive(&outstanding)) {
		*why = "keep-alive was sent while data was outstanding";
		return RESULT_FAIL;
	}

	fake_clock_set_ns(&active.state, 1000000000ULL);
	expected_seq = active.conn->seq - 1U;
	test_set_keepalive(active.ws, active.conn, 1000U,
			&active.state);
	fake_clock_advance_ms(&active.state, 600);
	fixture_incoming_spec(&active, &spec, 0, NULL, 0);
	fixture_deliver(&active, build_tcp_packet(&spec, &active.state));
	free_output(&active.state);
	fake_clock_advance_ms(&active.state, 500);
	fixture_run_timers(&active);
	if (active.state.out_cnt != 0) {
		*why = "keep-alive ignored recently received ACK activity";
		return RESULT_FAIL;
	}
	fake_clock_advance_ms(&active.state, 501);
	fixture_run_timers(&active);
	if (!fixture_has_keepalive_probe(&active, expected_seq)) {
		*why = "keep-alive was not sent after the connection became idle";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_keepalive_interval_setting(const char **why)
{
	struct fixture f;
	uint32_t expected_seq;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	expected_seq = f.conn->seq - 1U;
	test_set_keepalive(f.ws, f.conn, 3000U, &f.state);
	fake_clock_advance_ms(&f.state, 1001);
	fixture_run_timers(&f);
	if (f.state.out_cnt != 0) {
		*why = "keep-alive was sent before the configured interval";
		return RESULT_FAIL;
	}
	test_set_keepalive(f.ws, f.conn, 1000U, &f.state);
	fake_clock_advance_ms(&f.state, 1001);
	fixture_run_timers(&f);
	if (!fixture_has_keepalive_probe(&f, expected_seq)) {
		*why = "updated keep-alive interval was not applied";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_keepalive_default_interval(const char **why)
{
	struct fixture f;
	uint32_t expected_seq, interval;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	interval = f.conn->keepalive_interval_ms;
	if (interval < 2U * 60U * 60U * 1000U) {
		*why = "default keep-alive interval is less than two hours";
		return RESULT_FAIL;
	}
	fake_clock_set_ns(&f.state, 1000000000ULL);
	expected_seq = f.conn->seq - 1U;
	test_set_keepalive(f.ws, f.conn, interval, &f.state);
	/* The interval MUST be no less than two hours, so a probe is
	 * forbidden only strictly before the interval has elapsed. */
	fake_clock_advance_ms(&f.state, interval - 1U);
	fixture_run_timers(&f);
	if (fixture_has_keepalive_probe(&f, expected_seq)) {
		*why = "default keep-alive fired before its configured idle interval";
		return RESULT_FAIL;
	}
	fake_clock_advance_ms(&f.state, 1001);
	fixture_run_timers(&f);
	if (!fixture_has_keepalive_probe(&f, expected_seq)) {
		*why = "default keep-alive interval was not used";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_keepalive_probe_loss(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    if (!fixture_init(&f)) return RESULT_ERROR;
    uint32_t expected_seq = f.conn->seq - 1U;
    test_set_keepalive(f.ws, f.conn, 1000U, &f.state);
    fake_clock_advance_ms(&f.state, 1001);
    fixture_run_timers(&f);
    if (!fixture_has_keepalive_probe(&f, expected_seq)) {
        *why = "initial keep-alive probe missing"; return RESULT_FAIL;
    }
    free_output(&f.state); /* Lose just this probe. */
    fake_clock_advance_ms(&f.state, 1001);
    fixture_run_timers(&f);
    if (f.conn->state != II_TCP_STATE_ESTABLISHED) {
        *why = "one lost keep-alive probe closed the connection"; return RESULT_FAIL;
    }
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, f.conn->seq_next_expected, NULL, 0);
    spec.ack_seq = f.conn->acked_seq;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    free_output(&f.state);
    fake_clock_advance_ms(&f.state, 1001);
    fixture_run_timers(&f);
    if (f.conn->state != II_TCP_STATE_ESTABLISHED ||
            test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED)) {
        *why = "connection did not survive probe response recovery"; return RESULT_FAIL;
    }
    return RESULT_PASS;
}

static enum result test_urgent_pointer_support(const char **why)
{
	static const uint8_t first_payload[4] = { 0, 1, 2, 3 };
	static const uint8_t second_payload[2] = { 4, 5 };
	static const uint8_t third_payload[2] = { 6, 7 };
	struct fixture f;
	struct tcp_packet_spec spec;

	if (!fixture_init(&f))
		return RESULT_FAIL;

	/* The absolute urgent boundary is SEG.SEQ + SEG.UP. */
	fixture_incoming_spec(&f, &spec, 0, first_payload,
			sizeof(first_payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 3;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_urgent_boundary_is(&f, 3)) {
		*why = "the received urgent pointer was not retained";
		return RESULT_FAIL;
	}

	/* A later segment may advance the urgent boundary beyond its payload. */
	fixture_incoming_spec(&f, &spec, 4, second_payload,
			sizeof(second_payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 4;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_urgent_boundary_is(&f, 8)) {
		*why = "an advancing urgent pointer was not retained";
		return RESULT_FAIL;
	}

	/* A stale pointer must not move the connection's urgent boundary back. */
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 6, third_payload,
			sizeof(third_payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	/* RFC 9293 3.10.7.4 permits signalling whenever RCV.UP is ahead of
	 * the consumed data, so a notification here is not itself an error;
	 * what matters is that the boundary does not move backward. */
	if (!test_urgent_boundary_is(&f, 8)) {
		*why = "a stale urgent pointer moved the boundary backward";
		return RESULT_FAIL;
	}

	/* Pointer arithmetic and ordering must work across 32-bit wraparound. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.conn->seq_next_expected = UINT32_MAX - 2;
	f.conn->ack_seq = f.conn->seq_next_expected;
	fixture_incoming_spec(&f, &spec, UINT32_MAX - 2, first_payload,
			sizeof(first_payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 4;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_urgent_boundary_is(&f, 1)) {
		*why = "urgent pointer arithmetic failed across sequence wraparound";
		return RESULT_FAIL;
	}

	/* An URG segment that arrives out of order is processed when the gap
	 * is filled and the segment is taken from the out-of-order queue. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 4, second_payload,
			sizeof(second_payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 2;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_incoming_spec(&f, &spec, 0, first_payload,
			sizeof(first_payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->seq_next_expected != 6 || !test_urgent_boundary_is(&f, 6)) {
		*why = "the urgent pointer of a reordered segment was not retained";
		return RESULT_FAIL;
	}

	return RESULT_PASS;
}

static enum result test_arbitrary_urgent_sequence(const char **why)
{
	static const uint8_t payloads[][4] = {
		{ 0, 1, 2, 3 },
		{ 4, 5, 6, 7 },
		{ 8, 9, 10, 11 },
	};
	struct fixture f;
	struct tcp_packet_spec spec;
	unsigned int i;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);

	/* Repeated maximum-width pointers extend one urgent sequence beyond
	 * the range representable by a single 16-bit Urgent Pointer field. */
	for (i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
		fixture_incoming_spec(&f, &spec, i * sizeof(payloads[0]),
				payloads[i], sizeof(payloads[i]));
		spec.tcp_flags |= TEST_TCP_URG;
		spec.urgent_pointer = UINT16_MAX;
		fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
		if (!test_urgent_boundary_is(&f, UINT16_MAX +
					i * sizeof(payloads[0])) ||
				test_event_count(&f.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_TCP_URGENT) != i + 1) {
			*why = "a multi-segment urgent sequence was truncated";
			return RESULT_FAIL;
		}
	}

	if (f.state.next_payload != sizeof(payloads) ||
			f.conn->seq_next_expected != sizeof(payloads)) {
		*why = "data in a long urgent sequence was not delivered in order";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_urgent_queue_query(const char **why)
{
	static const uint8_t first_payload[2] = { 0, 1 };
	static const uint8_t second_payload[3] = { 2, 3, 4 };
	struct fixture f;
	struct tcp_packet_spec spec;
	uint32_t queued;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	if (test_tcp_urgent_query(&f.state, f.conn, &queued) || queued != 0) {
		*why = "a new connection reported queued urgent data";
		return RESULT_FAIL;
	}

	/* An URG indication may announce an urgent boundary ahead of data that
	 * has reached RCV.NXT. */
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 5;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_tcp_urgent_query(&f.state, f.conn, &queued) || queued != 5) {
		*why = "the announced urgent sequence was not queryable";
		return RESULT_FAIL;
	}

	/* As data is received, the reported amount decreases to the boundary. */
	fixture_incoming_spec(&f, &spec, 0, first_payload,
			sizeof(first_payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_tcp_urgent_query(&f.state, f.conn, &queued) || queued != 3) {
		*why = "the urgent queue amount did not follow received data";
		return RESULT_FAIL;
	}
	fixture_incoming_spec(&f, &spec, 2, second_payload,
			sizeof(second_payload));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (test_tcp_urgent_query(&f.state, f.conn, &queued) || queued != 0) {
		*why = "urgent data remained reported after reaching its boundary";
		return RESULT_FAIL;
	}

	/* Query arithmetic must preserve the amount across sequence wrap. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.conn->seq_next_expected = UINT32_MAX - 1;
	f.conn->ack_seq = f.conn->seq_next_expected;
	fixture_incoming_spec(&f, &spec, UINT32_MAX - 1, NULL, 0);
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 3;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_tcp_urgent_query(&f.state, f.conn, &queued) || queued != 3) {
		*why = "urgent queue query failed across sequence wraparound";
		return RESULT_FAIL;
	}

	return RESULT_PASS;
}

static enum result test_urgent_pointer_semantics(const char **why)
{
	static const uint8_t payload[5] = { 0, 1, 2, 3, 4 };
	struct fixture f;
	struct tcp_packet_spec spec;

	/* SEG.UP=3 means that SEQ+3, not SEQ+2, is first non-urgent. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.conn->seq_next_expected = 100;
	f.conn->ack_seq = 100;
	fixture_incoming_spec(&f, &spec, 100, payload, sizeof(payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 3;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!f.state.urgent.valid) {
		*why = "the URG flag was not processed";
		return RESULT_FAIL;
	}
	if (!test_urgent_boundary_is(&f, 103)) {
		*why = "URG pointer was interpreted as the last urgent octet";
		return RESULT_FAIL;
	}

	/* A pointer equal to data length identifies the octet after the segment. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.conn->seq_next_expected = 200;
	f.conn->ack_seq = (uint32_t)200;
	fixture_incoming_spec(&f, &spec, 200, payload, sizeof(payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = sizeof(payload);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_urgent_boundary_is(&f, 205)) {
		*why = "the first non-urgent octet after a segment was misidentified";
		return RESULT_FAIL;
	}

	/* The same first-non-urgent convention applies across sequence wrap. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.conn->seq_next_expected = UINT32_MAX - 1;
	f.conn->ack_seq = f.conn->seq_next_expected;
	fixture_incoming_spec(&f, &spec, UINT32_MAX - 1, payload, 2);
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 2;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_urgent_boundary_is(&f, 0)) {
		*why = "first non-urgent octet was misidentified across wraparound";
		return RESULT_FAIL;
	}

	return RESULT_PASS;
}

static int fixture_close_receive_window(struct fixture *f)
{
	void *pkt;
	void *opaque = &f->state;

	f->conn->buf.used = f->conn->buf.capacity;
	pkt = fixture_packet(f, 0, 0, 0);
	if (!pkt)
		return 0;
	if (ii_ntohs(PB_TCP(pkt)->win_be) != 0) {
		iip_ops_pkt_free(pkt, opaque);
		return 0;
	}
	iip_ops_pkt_free(pkt, opaque);
	return 1;
}

static enum result test_rst_urg_with_zero_window(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;

	/* A zero-length URG segment at RCV.NXT remains acceptable at zero
	 * receive window and must update/report the urgent boundary. */
	if (!fixture_init(&f) || !fixture_close_receive_window(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 5;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.conn->state != II_TCP_STATE_ESTABLISHED ||
			!test_urgent_boundary_is(&f, 5) ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_URGENT) != 1) {
		*why = "URG was not processed while the receive window was zero";
		return RESULT_FAIL;
	}

	/* RST processing must likewise be independent of receive-window space. */
	if (!fixture_init(&f) || !fixture_close_receive_window(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, NULL, 0);
	spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (!test_event_has_state_transition(&f.state, f.conn,
				II_TCP_STATE_ESTABLISHED,
				II_TCP_STATE_CLOSED) ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) != 1) {
		*why = "RST was not processed while the receive window was zero";
		return RESULT_FAIL;
	}

	return RESULT_PASS;
}

static enum result test_async_urgent_notification(const char **why)
{
	static const uint8_t payload[4] = { 0, 1, 2, 3 };
	static const uint8_t next_payload[2] = { 4, 5 };
	struct fixture f;
	struct tcp_packet_spec spec;
	const struct test_event *event;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 3;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_TCP_URGENT, 0);
	if (!event || event->object != f.conn || !event->value[0] ||
			!event->value[1] || event->value[2] != 0 ||
			event->value[3] != 3 ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_URGENT) != 1 ||
			!test_urgent_boundary_is(&f, 3)) {
		*why = "URG arrival was not reported to the application";
		return RESULT_FAIL;
	}

	/* Retransmitting the same urgent indication must not notify it twice. */
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 3;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_TCP_URGENT) != 0) {
		*why = "a retransmitted urgent indication was reported twice";
		return RESULT_FAIL;
	}

	/* A pointer that advances with subsequent data generates a new notice. */
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 4, next_payload,
			sizeof(next_payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 2;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_TCP_URGENT, 0);
	if (!event || event->value[2] != 4 || event->value[3] != 2 ||
			!test_urgent_boundary_is(&f, 6) ||
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_URGENT) != 1) {
		*why = "an advancing urgent pointer was not reported";
		return RESULT_FAIL;
	}

	/* Sequence wraparound must not suppress a genuinely advancing pointer. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	f.conn->seq_next_expected = UINT32_MAX - 2;
	f.conn->ack_seq = f.conn->seq_next_expected;
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, UINT32_MAX - 2, payload,
			sizeof(payload));
	spec.tcp_flags |= TEST_TCP_URG;
	spec.urgent_pointer = 4;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_TCP_URGENT) != 1 || !test_urgent_boundary_is(&f, 1)) {
		*why = "urgent notification failed across sequence wraparound";
		return RESULT_FAIL;
	}

	/* A segment without URG must not generate the asynchronous notice. */
	if (!fixture_init(&f))
		return RESULT_FAIL;
	test_event_log_clear(&f.state);
	fixture_incoming_spec(&f, &spec, 0, payload, 1);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_TCP_URGENT) != 0) {
		*why = "a non-URG segment generated an urgent notification";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_invalid_open_destination(const char **why)
{
	static const uint32_t invalid_destinations[] = {
		0x00000000U, 0xe0000001U, 0xffffffffU,
	};
	unsigned int i;
	(void)why;
	for (i = 0; i < sizeof(invalid_destinations) /
			sizeof(invalid_destinations[0]); i++) {
		struct fixture f;
		if (!fixture_init(&f))
			return RESULT_FAIL;
		test_event_log_clear(&f.state);
		test_api_connect(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]),
				ii_htons(11000 + i), f.peer_mac,
				ii_htonl(invalid_destinations[i]),
				ii_htons(22000), &f.state);
		if (test_event_count(&f.state, TEST_EVENT_STATE_TRANSITION, 0) != 0)
			return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_unknown_ip_option(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	const uint8_t unknown_ip_option[] = { 0x9e, 4, 0xaa, 0xbb };
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	memcpy(spec.ip_options, unknown_ip_option, sizeof(unknown_ip_option));
	spec.ip_options_len = sizeof(unknown_ip_option);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.state.payload_chunk_count == 1 && f.conn->seq_next_expected == 1
		? RESULT_PASS : RESULT_FAIL;
}

static uint16_t test_make_source_route_option(uint8_t option[40],
		uint8_t kind, uint8_t pointer, const uint32_t address_be[],
		uint8_t address_count)
{
	uint16_t len = 3U + address_count * 4U;
	uint16_t padded_len = ROUND_UP(len, 4);
	assert((kind == 131 || kind == 137) && address_count &&
			padded_len <= 40);
	memset(option, 0, padded_len);
	option[0] = kind;
	option[1] = len;
	option[2] = pointer;
	memcpy(&option[3], address_be, address_count * sizeof(uint32_t));
	return padded_len;
}

static int test_tcp_checksum_valid_for_destination(void *pkt,
		uint32_t destination_be)
{
	struct iip_l4_ip4_pseudo_hdr pseudo;
	uint8_t *buffer[2];
	uint16_t len[2];
	uint16_t supplied = ii_ntohs(PB_TCP(pkt)->csum_be);
	pseudo.ip4_src_be = PB_IP4(pkt)->src_be;
	pseudo.ip4_dst_be = destination_be;
	pseudo.pad = 0;
	pseudo.proto = 6;
	len[1] = ii_ntohs(PB_IP4(pkt)->len_be) -
		(PB_IP4(pkt)->vl & 0x0f) * 4;
	pseudo.len_be = ii_htons(len[1]);
	buffer[0] = (uint8_t *)&pseudo;
	buffer[1] = (uint8_t *)PB_TCP(pkt);
	len[0] = sizeof(pseudo);
	return supplied == test_netcsum16(buffer, len, 2, supplied);
}

static int test_packet_has_source_route(void *pkt, uint32_t wire_dst_be,
		uint32_t ultimate_dst_be, const uint8_t *expected_option,
		uint16_t expected_option_len)
{
	const uint8_t *option;
	uint16_t option_len = 0;
	option = test_ip4_source_route_option(pkt, &option_len);
	return option && option_len == expected_option_len &&
		!memcmp(option, expected_option, expected_option_len) &&
		PB_IP4(pkt)->dst_be == wire_dst_be && ip4_checksum_valid(pkt) &&
		test_tcp_checksum_valid_for_destination(pkt, ultimate_dst_be);
}

static enum result test_application_source_route(const char **why)
{
	struct fixture f;
	struct ii_tcp_conn *conn;
	uint8_t option[40];
	uint16_t option_len;
	uint16_t local_port_be = ii_htons(14000);
	uint16_t peer_port_be = ii_htons(25001);
	uint32_t wire_dst_be = ii_htonl(0xcb007101U);
	uint32_t address_be[1];
	if (!fixture_init(&f))
		return RESULT_FAIL;
	address_be[0] = ii_htonl(f.conn->dst_ip[0]);
	option_len = test_make_source_route_option(option, 131, 4,
			address_be, 1);
	if (!test_source_route_add(&f.state, 1, ii_htonl(f.conn->src_ip[0]),
			local_port_be, ii_htonl(f.conn->dst_ip[0]), peer_port_be,
			wire_dst_be, option, option_len) ||
			test_tcp_active_open(f.ws, f.local_mac,
			&(uint32_t){ ii_htonl(f.conn->src_ip[0]) }, local_port_be, f.peer_mac,
			ii_htonl(f.conn->dst_ip[0]), peer_port_be, &f.state) == 0xffff)
		return RESULT_FAIL;
	conn = fixture_find_peer_port(&f, peer_port_be);
	fixture_run_timers(&f);
	if (!conn || f.state.out_cnt != 1 ||
			!PB_TCP_HDR_HAS_SYN(f.state.out[0]) ||
			!test_packet_has_source_route(f.state.out[0], wire_dst_be,
				ii_htonl(f.conn->dst_ip[0]), option, option_len)) {
		*why = "active OPEN did not apply the application source route";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_application_route_precedence(const char **why)
{
	struct fixture f;
	struct ii_tcp_conn *conn;
	struct tcp_packet_spec spec;
	uint8_t application_option[40], received_option[40];
	uint16_t application_option_len, received_option_len;
	uint16_t local_port_be = ii_htons(14001);
	uint16_t peer_port_be = ii_htons(25002);
	uint32_t application_hop_be = ii_htonl(0xcb007101U);
	uint32_t received_hop_be = ii_htonl(0xcb007102U);
	uint32_t address_be[1];
	if (!fixture_init(&f))
		return RESULT_FAIL;
	address_be[0] = ii_htonl(f.conn->dst_ip[0]);
	application_option_len = test_make_source_route_option(
			application_option, 131, 4, address_be, 1);
	if (!test_source_route_add(&f.state, 1, ii_htonl(f.conn->src_ip[0]),
			local_port_be, ii_htonl(f.conn->dst_ip[0]), peer_port_be,
			application_hop_be, application_option,
			application_option_len) ||
			test_tcp_active_open(f.ws, f.local_mac,
			&(uint32_t){ ii_htonl(f.conn->src_ip[0]) }, local_port_be, f.peer_mac,
			ii_htonl(f.conn->dst_ip[0]), peer_port_be, &f.state) == 0xffff)
		return RESULT_FAIL;
	conn = fixture_find_peer_port(&f, peer_port_be);
	fixture_run_timers(&f);
	if (!conn)
		return RESULT_FAIL;
	free_output(&f.state);
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.dst_port_be = local_port_be;
	spec.ack_seq = conn->seq;
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	address_be[0] = received_hop_be;
	received_option_len = test_make_source_route_option(received_option,
			131, 8, address_be, 1);
	memcpy(spec.ip_options, received_option, received_option_len);
	spec.ip_options_len = received_option_len;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.out_cnt != 1 || PB_TCP_HDR_HAS_SYN(f.state.out[0]) ||
			!test_packet_has_source_route(f.state.out[0],
				application_hop_be, ii_htonl(f.conn->dst_ip[0]),
				application_option, application_option_len)) {
		*why = "a received source route overrode the application route";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_passive_return_route(const char **why)
{
	struct fixture f;
	struct ii_tcp_conn *child;
	struct tcp_packet_spec spec;
	uint8_t received_option[40], expected_option[40];
	uint16_t received_option_len, expected_option_len;
	uint16_t peer_port_be = ii_htons(25003);
	uint32_t recorded_hop_be = ii_htonl(0xcb007103U);
	uint32_t address_be[1];
	if (!fixture_init(&f))
		return RESULT_FAIL;
	address_be[0] = recorded_hop_be;
	received_option_len = test_make_source_route_option(received_option,
			131, 8, address_be, 1);
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	memcpy(spec.ip_options, received_option, received_option_len);
	spec.ip_options_len = received_option_len;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	child = fixture_find_peer_port(&f, peer_port_be);
	address_be[0] = ii_htonl(f.conn->dst_ip[0]);
	expected_option_len = test_make_source_route_option(expected_option,
			131, 4, address_be, 1);
	if (!child || f.state.out_cnt != 1 ||
			!PB_TCP_HDR_HAS_SYN(f.state.out[0]) ||
			!PB_TCP_HDR_HAS_ACK(f.state.out[0]) ||
			!test_packet_has_source_route(f.state.out[0],
				recorded_hop_be, ii_htonl(f.conn->dst_ip[0]),
				expected_option, expected_option_len)) {
		*why = "SYN-ACK did not use the received return route";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	fixture_incoming_spec(&f, &spec, 101, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.ack_seq = child->seq;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	free_output(&f.state);
	test_api_push(f.ws, child, NULL, 0, 1, 0, 0, 0, NULL,
			0, &f.state);
	fixture_run_timers(&f);
	if (!child->opaque || f.state.out_cnt != 1 ||
			!test_packet_has_source_route(f.state.out[0],
				recorded_hop_be, ii_htonl(f.conn->dst_ip[0]),
				expected_option, expected_option_len)) {
		*why = "the return route was not retained in tcp_opaque";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_icmp_processing(const char **why)
{
	struct fixture f;
	void *pkt;
	uint16_t next_hop_mtu_be = ii_htons(1200);
	uint32_t seq_before, ack_before, expected_before;
	uint16_t path_mtu_before;
	if (!fixture_init(&f) || !fixture_prepare_icmp(&f))
		return RESULT_FAIL;
	seq_before = ii_htonl(f.conn->seq);
	ack_before = ii_htonl(f.conn->ack_seq);
	expected_before = f.conn->seq_next_expected;
	path_mtu_before = f.conn->path_mtu;
	test_event_log_clear(&f.state);
	pkt = fixture_icmp_error_packet(&f, 3, 4);
	memcpy(&PB_ICMP(pkt)->rest[2], &next_hop_mtu_be,
			sizeof(next_hop_mtu_be));
	{
            uint8_t *qbuf[1] = { (uint8_t *)PB_ICMP_DATA(pkt) };
            uint16_t qlen[1] = { 20 };
            struct iip_ip4_hdr *q = (struct iip_ip4_hdr *)qbuf[0];
            q->csum_be = 0;
            q->csum_be = ii_htons(test_netcsum16(qbuf, qlen, 1, 0));
        }
        update_icmp_checksum(pkt);
	fixture_deliver(&f, pkt);
	if (f.conn->path_mtu == path_mtu_before &&
			test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR) == 0) {
		*why = "an ICMP Fragmentation Needed error was not acted on or reported for the connection";
		return RESULT_FAIL;
	}
	return f.conn->state == II_TCP_STATE_ESTABLISHED &&
		ii_htonl(f.conn->seq) == seq_before && ii_htonl(f.conn->ack_seq) == ack_before &&
		f.conn->seq_next_expected == expected_before &&
		/*
		 * The error must be acted on and directed to the connection
		 * (MUST-54).  Adopting the reported MTU (PMTUD, a SHOULD) or
		 * reporting the error to the application both qualify.
		 */
		(f.conn->path_mtu == 1200 ||
		 (f.conn->path_mtu == path_mtu_before &&
		  test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR) == 1)) &&
		f.state.out_cnt == 0 &&
		test_event_count(&f.state, TEST_EVENT_STATE_TRANSITION, 0) == 0 &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 0
		? RESULT_PASS : RESULT_FAIL;
}

static enum result test_source_quench_discard(const char **why)
{
	struct fixture f;
	uint8_t state_before;
	uint32_t seq_before, ack_before, expected_before, path_mtu_before;
	unsigned int payload_before;
	(void)why;
	if (!fixture_init(&f) || !fixture_prepare_icmp(&f))
		return RESULT_FAIL;
	state_before = f.conn->state;
	seq_before = ii_htonl(f.conn->seq);
	ack_before = ii_htonl(f.conn->ack_seq);
	expected_before = f.conn->seq_next_expected;
	path_mtu_before = f.conn->path_mtu;
	payload_before = f.state.payload_chunk_count;
	test_event_log_clear(&f.state);
	fixture_deliver(&f, fixture_icmp_error_packet(&f, 4, 0));
	return f.conn->state == state_before && ii_htonl(f.conn->seq) == seq_before &&
		ii_htonl(f.conn->ack_seq) == ack_before &&
		f.conn->seq_next_expected == expected_before &&
		f.conn->path_mtu == path_mtu_before &&
		f.state.payload_chunk_count == payload_before && f.state.out_cnt == 0 &&
		test_event_count(&f.state, TEST_EVENT_TX_PACKET, 0) == 0 &&
		test_event_count(&f.state, TEST_EVENT_STATE_TRANSITION, 0) == 0 &&
		test_event_count(&f.state, TEST_EVENT_CALLBACK, 0) == 0 &&
		test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0) == 0 &&
		test_event_count(&f.state, TEST_EVENT_LOSS_DETECTED, 0) == 0
		? RESULT_PASS : RESULT_FAIL;
}

static enum result test_soft_icmp_does_not_abort(const char **why)
{
	static const struct {
		uint8_t type;
		uint8_t code;
	} soft_errors[] = {
		{ 3, 0 }, { 3, 1 }, { 3, 5 }, /* Destination Unreachable */
		{ 11, 0 }, { 11, 1 },         /* Time Exceeded */
		{ 12, 0 }, { 12, 1 }, { 12, 2 }, /* Parameter Problem */
	};
	unsigned int i;
	(void)why;
	for (i = 0; i < sizeof(soft_errors) / sizeof(soft_errors[0]); i++) {
		struct fixture f;
		uint32_t seq_before, ack_before, expected_before;
		if (!fixture_init(&f) || !fixture_prepare_icmp(&f))
			return RESULT_FAIL;
		seq_before = ii_htonl(f.conn->seq);
		ack_before = ii_htonl(f.conn->ack_seq);
		expected_before = f.conn->seq_next_expected;
		test_event_log_clear(&f.state);
		fixture_deliver(&f, fixture_icmp_error_packet(&f,
				soft_errors[i].type, soft_errors[i].code));
		if (f.conn->state != II_TCP_STATE_ESTABLISHED ||
				ii_htonl(f.conn->seq) != seq_before ||
				ii_htonl(f.conn->ack_seq) != ack_before ||
				f.conn->seq_next_expected != expected_before ||
				f.state.out_cnt != 0 ||
				test_event_count(&f.state, TEST_EVENT_TX_PACKET, 0) != 0 ||
				test_event_count(&f.state,
					TEST_EVENT_STATE_TRANSITION, 0) != 0 ||
				test_event_count(&f.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_CLOSED) != 0)
			return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result icmp_notification_case(unsigned first, unsigned count, const char **why)
{
	static const struct {
		uint8_t type;
		uint8_t code;
	} errors[] = {
		{ 3, 0 }, { 3, 1 }, { 3, 4 }, { 3, 5 },
		{ 11, 0 }, { 11, 1 },
		{ 12, 0 }, { 12, 1 }, { 12, 2 },
	};
	unsigned int i;
	(void)why;

	for (i = first; i < first + count; i++) {
		struct fixture f;
		const struct test_event *event;
		if (!fixture_init(&f) || !fixture_prepare_icmp(&f))
			return RESULT_FAIL;
		test_event_log_clear(&f.state);
		fixture_deliver(&f, fixture_icmp_error_packet(&f,
				errors[i].type, errors[i].code));
		event = test_event_nth(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR, 0);
		if (!event) {
			fprintf(stderr, "MUST-47: ICMP type %u code %u was not reported\n",
					errors[i].type, errors[i].code);
			*why = "an ICMP error for the connection was not reported to the application";
			return RESULT_FAIL;
		}
		if (event->object != f.conn ||
				event->value[0] != errors[i].type ||
				event->value[1] != errors[i].code ||
				!event->value[2] || !event->value[3] ||
				test_event_count(&f.state, TEST_EVENT_CALLBACK,
					TEST_CALLBACK_TCP_ICMP_ERROR) != 1)
			return RESULT_FAIL;
		/* Destination Unreachable codes 2-4 are hard errors that SHOULD
		 * abort the connection (RFC 9293 Section 3.9.2.2); code 4 may
		 * instead be handled by PMTUD.  Other errors must not abort. */
		if (f.conn->state != II_TCP_STATE_ESTABLISHED &&
				!(errors[i].type == 3 && errors[i].code >= 2 &&
					errors[i].code <= 4))
			return RESULT_FAIL;
	}

	{
		struct fixture f;
		void *pkt;
		struct iip_ip4_hdr *quoted_ip4;
		struct iip_tcp_hdr *quoted_tcp;
		if (!fixture_init(&f) || !fixture_prepare_icmp(&f))
			return RESULT_FAIL;

		/* A quoted non-TCP packet must not be associated with a TCP connection. */
		test_event_log_clear(&f.state);
		pkt = fixture_icmp_error_packet(&f, 11, 0);
		quoted_ip4 = (struct iip_ip4_hdr *)PB_ICMP_DATA(pkt);
		quoted_ip4->proto = 17;
		{
            uint8_t *qbuf[1] = { (uint8_t *)PB_ICMP_DATA(pkt) };
            uint16_t qlen[1] = { 20 };
            struct iip_ip4_hdr *q = (struct iip_ip4_hdr *)qbuf[0];
            q->csum_be = 0;
            q->csum_be = ii_htons(test_netcsum16(qbuf, qlen, 1, 0));
        }
        update_icmp_checksum(pkt);
		fixture_deliver(&f, pkt);
		if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR) != 0)
			return RESULT_FAIL;

		/* A non-initial fragment does not contain usable TCP ports. */
		test_event_log_clear(&f.state);
		pkt = fixture_icmp_error_packet(&f, 11, 0);
		quoted_ip4 = (struct iip_ip4_hdr *)PB_ICMP_DATA(pkt);
		quoted_ip4->off_be = ii_htons(1);
		{
            uint8_t *qbuf[1] = { (uint8_t *)PB_ICMP_DATA(pkt) };
            uint16_t qlen[1] = { 20 };
            struct iip_ip4_hdr *q = (struct iip_ip4_hdr *)qbuf[0];
            q->csum_be = 0;
            q->csum_be = ii_htons(test_netcsum16(qbuf, qlen, 1, 0));
        }
        update_icmp_checksum(pkt);
		fixture_deliver(&f, pkt);
		if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR) != 0)
			return RESULT_FAIL;

		/* The initial fragment remains identifiable even with MF set. */
		test_event_log_clear(&f.state);
		pkt = fixture_icmp_error_packet(&f, 11, 0);
		quoted_ip4 = (struct iip_ip4_hdr *)PB_ICMP_DATA(pkt);
		quoted_ip4->off_be = ii_htons(0x2000);
		{
            uint8_t *qbuf[1] = { (uint8_t *)PB_ICMP_DATA(pkt) };
            uint16_t qlen[1] = { 20 };
            struct iip_ip4_hdr *q = (struct iip_ip4_hdr *)qbuf[0];
            q->csum_be = 0;
            q->csum_be = ii_htons(test_netcsum16(qbuf, qlen, 1, 0));
        }
        update_icmp_checksum(pkt);
		fixture_deliver(&f, pkt);
		if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR) != 1)
			return RESULT_FAIL;

		/* A different quoted 4-tuple must not select this connection. */
		test_event_log_clear(&f.state);
		pkt = fixture_icmp_error_packet(&f, 12, 0);
		quoted_ip4 = (struct iip_ip4_hdr *)PB_ICMP_DATA(pkt);
		quoted_tcp = (struct iip_tcp_hdr *)((uint8_t *)quoted_ip4 +
				(quoted_ip4->vl & 0x0f) * 4);
		quoted_tcp->dst_be ^= ii_htons(1);
		{
            uint8_t *qbuf[1] = { (uint8_t *)PB_ICMP_DATA(pkt) };
            uint16_t qlen[1] = { 20 };
            struct iip_ip4_hdr *q = (struct iip_ip4_hdr *)qbuf[0];
            q->csum_be = 0;
            q->csum_be = ii_htons(test_netcsum16(qbuf, qlen, 1, 0));
        }
        update_icmp_checksum(pkt);
		fixture_deliver(&f, pkt);
		if (test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_TCP_ICMP_ERROR) != 0)
			return RESULT_FAIL;
	}

	return RESULT_PASS;
}

static enum result test_tcp_icmp_error_notification(const char **why)
{
    return icmp_notification_case(0, 9, why);
}

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
		fake_clock_advance_ms(&f.state, 1);
		fixture_run_timers(&f);
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

	fake_clock_advance_ms(&f.state, (uint64_t)initial_rto + 1);
	fixture_run_timers(&f);
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
	fake_clock_advance_ms(&f.state, 99);
	fixture_run_timers(&f);
	if (f.state.out_cnt || (f.conn->flags & II_TCP_CONN_FLAGS_SET_PROBE) ||
			!test_ring_end(f.ws, &f.conn->tx_ring, 0)) {
		*why = "SWS override sent data before 0.1 seconds";
		return 0;
	}
	for (i = 0; i < 10 && !f.state.out_cnt; i++) {
		fake_clock_advance_ms(&f.state, 100);
		fixture_run_timers(&f);
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
 * test.  iip announces a fixed receive-window shift of 7 (the shift passed
 * to ii_tcp_compute_win), independent of conn->ws, so the white-box fixture
 * interprets the field with that implementation constant.
 */
#define TEST_IIP_RX_WINDOW_SHIFT 7U
static int fixture_advertise_window(struct fixture *f, uint32_t expected)
{
	void *pkt = fixture_packet(f, 0, 0, 0);
	uint32_t window;
	int ok;

	if (!pkt)
		return 0;
	window = (uint32_t)ii_ntohs(PB_TCP(pkt)->win_be) <<
		TEST_IIP_RX_WINDOW_SHIFT;
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
		fake_clock_advance_ms(&f.state, 1); fixture_run_timers(&f);
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
			fake_clock_advance_ms(&f.state, 499);
			fixture_run_timers(&f);
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
			fake_clock_advance_ms(&f.state, 499);
			fixture_run_timers(&f);
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
	fake_clock_advance_ms(&f.state, 10);
	fixture_run_timers(&f);
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
	(void)why;
	return ii_ntohs(test_compute_tcp_window(65535, 0)) == 65535
		? RESULT_PASS : RESULT_FAIL;
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
	return valid ? RESULT_PASS : RESULT_FAIL;
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
	fake_clock_advance_ms(&f.state, (uint64_t)initial_rto + 1);
	fixture_run_timers(&f);
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


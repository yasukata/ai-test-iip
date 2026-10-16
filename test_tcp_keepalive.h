/* Keep-alive configuration, timing, and probe loss.
 * Included in dependency order by test_tcp.h.
 */

static enum result test_keepalive_default_off(const char **why)
{
	struct fixture f;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fake_clock_set_ns(&f.state, 1000000000ULL);
	fixture_run_timers(&f);
	test_event_log_clear(&f.state);
	fake_clock_advance_sec(&f.state, 2 * 60 * 60 + 1);
	fixture_run_timers(&f);
	TEST_REQUIRE(why, test_event_count(&f.state, TEST_EVENT_TIMER, 0) > 0,
        "default-off: expected timer observations, actual=0");
    TEST_REQUIRE(why, test_event_count(&f.state, TEST_EVENT_TX_PACKET, 0) == 0,
        "default-off: expected TX packets=0, actual=%u",
        test_event_count(&f.state, TEST_EVENT_TX_PACKET, 0));
    return RESULT_PASS;
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
	fixture_advance_ms(&enabled, 2000);
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
	fixture_advance_ms(&outstanding, 1001);
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
	fixture_advance_ms(&active, 500);
	if (active.state.out_cnt != 0) {
		*why = "keep-alive ignored recently received ACK activity";
		return RESULT_FAIL;
	}
	fixture_advance_ms(&active, 501);
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
	fixture_advance_ms(&f, 1001);
	if (f.state.out_cnt != 0) {
		*why = "keep-alive was sent before the configured interval";
		return RESULT_FAIL;
	}
	test_set_keepalive(f.ws, f.conn, 1000U, &f.state);
	fixture_advance_ms(&f, 1001);
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
	TEST_REQUIRE(why, interval >= 2U * 60U * 60U * 1000U,
        "default keep-alive interval: expected >=7200000 ms, actual=%u ms", interval);
	fake_clock_set_ns(&f.state, 1000000000ULL);
	expected_seq = f.conn->seq - 1U;
	test_set_keepalive(f.ws, f.conn, interval, &f.state);
	/* The interval MUST be no less than two hours, so a probe is
	 * forbidden only strictly before the interval has elapsed. */
	fixture_advance_ms(&f, interval - 1U);
	if (fixture_has_keepalive_probe(&f, expected_seq)) {
		*why = "default keep-alive fired before its configured idle interval";
		return RESULT_FAIL;
	}
	fixture_advance_ms(&f, 1001);
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
    fixture_advance_ms(&f, 1001);
    if (!fixture_has_keepalive_probe(&f, expected_seq)) {
        *why = "initial keep-alive probe missing"; return RESULT_FAIL;
    }
    free_output(&f.state); /* Lose just this probe. */
    fixture_advance_ms(&f, 1001);
    if (f.conn->state != II_TCP_STATE_ESTABLISHED) {
        *why = "one lost keep-alive probe closed the connection"; return RESULT_FAIL;
    }
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, f.conn->seq_next_expected, NULL, 0);
    spec.ack_seq = f.conn->acked_seq;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    free_output(&f.state);
    fixture_advance_ms(&f, 1001);
    if (f.conn->state != II_TCP_STATE_ESTABLISHED ||
            test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED)) {
        *why = "connection did not survive probe response recovery"; return RESULT_FAIL;
    }
    return RESULT_PASS;
}


/* Urgent pointer semantics and application notifications.
 * Included in dependency order by test_tcp.h.
 */

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


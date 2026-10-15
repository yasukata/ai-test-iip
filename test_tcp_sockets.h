/* Listen and address selection, abort notifications, and TIME-WAIT.
 * Included in dependency order by test_tcp.h.
 */

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
	fixture_advance_ms(&f, IIP_CONF_TCP_MSL_SEC * 2000ULL - 1);
	if (f.conn->state != II_TCP_STATE_TIME_WAIT)
		return 0;
	fixture_advance_ms(&f, 1);
	if (f.conn->state == II_TCP_STATE_CLOSED) return 1;
	/* iip slow timer granularity: allow its next invocation after expiry. */
	fixture_advance_ms(&f, 1000);
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


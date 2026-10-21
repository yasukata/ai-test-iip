/* TCP network-layer interaction, source routing, and ICMP errors.
 * Included in dependency order by test_tcp.h.
 */

static enum result test_invalid_open_destination(const char **why)
{
	static const uint32_t invalid_destinations[] = {
		0x00000000U, 0xe0000001U, 0xffffffffU,
	};
	unsigned int i;
	int ok = 1;
	(void)why;
	for (i = 0; i < sizeof(invalid_destinations) /
			sizeof(invalid_destinations[0]); i++) {
		struct fixture f;
		if (!fixture_init(&f))
			return RESULT_FAIL;
		/* Positive control proves OPEN/RUN reaches native wire output. The
		 * connect adapter does not emit state-transition events. */
		TEST_REQUIRE(why, test_api_connect(f.ws, f.local_mac, ii_htonl(0xc0000201U),
				ii_htons(12000), f.peer_mac, ii_htonl(0xc6336402U),
				ii_htons(22000), &f.state) == 0, "valid OPEN control rejected");
		fixture_run_timers(&f);
		TEST_REQUIRE(why, f.state.out_cnt && PB_TCP_HDR_HAS_SYN(f.state.out[0]),
				"valid OPEN control produced no SYN");
		free_output(&f.state);
		uint16_t rc = test_api_connect(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]),
				ii_htons(11000 + i), f.peer_mac,
				ii_htonl(invalid_destinations[i]),
				ii_htons(22000), &f.state);
		fixture_run_timers(&f);
		TEST_ACCUMULATE(ok, rc == UINT16_MAX && f.state.out_cnt == 0,
				"invalid destination %08x: expected OPEN error and no SYN, actual rc=%u outputs=%u",
				invalid_destinations[i], rc, f.state.out_cnt);
		free_output(&f.state);
	}
	return ok ? RESULT_PASS : RESULT_FAIL;
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


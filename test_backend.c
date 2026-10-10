/* Included after the packet backend; bindings share the test translation unit. */

static int test_backend_ethernet_header(uint8_t *buf, uint8_t *dst, uint16_t proto, void *opaque)
{
	struct test_state *state = opaque;
	memcpy(buf, dst, 6);
	memcpy(buf + 6, state->local_mac, 6);
	memcpy(buf + 12, &proto, 2);
	return 0;
}

static bool test_backend_ethernet_match(uint8_t *buf, void *opaque)
{
	return !memcmp(buf, ((struct test_state *)opaque)->local_mac, 6);
}

static bool test_backend_ipv4_match(uint8_t *buf, void *opaque)
{
	return !memcmp(buf, &((struct test_state *)opaque)->local_ip4_be, 4);
}

static int test_backend_arp(struct iip_workspace *w, void *pkt, void *opaque)
{
	iip_ops_arp_reply(w, pkt, opaque);
	return 0;
}

static bool test_backend_accept(struct iip_workspace *w, uint32_t id, void *opaque)
{
	return iip_ops_tcp_accept(w, &w->pbs.array[id], opaque);
}

static int test_backend_udp(struct iip_workspace *w, uint32_t id, void *opaque)
{
	struct ii_pb *p = &w->pbs.array[id];
	/* Count one datagram callback, including payload distributed over fragments. */
	iip_ops_udp_payload(w, p, opaque);
	return 0;
}

static bool test_backend_fastopen(struct iip_workspace *w, uint32_t id, const uint8_t *cookie, uint8_t len)
{
	struct ii_tcp_conn *conn = &w->tcp_conns.array[id];
	return test_tcp_fastopen_check(ii_htonl(conn->dst_ip[0]), ii_htonl(conn->src_ip[0]), cookie, len) == 0;
}

static int test_backend_tcp_payload(struct iip_workspace *w,
		uint32_t id, uint32_t pb_id, void *opaque)
{
	struct ii_tcp_conn *conn = &w->tcp_conns.array[id];
	struct ii_pb *p = &w->pbs.array[pb_id];
	uint8_t payload[UINT16_MAX];
	uint16_t copied;
	uint16_t len = p->tcp.payload_len - p->tcp.inc_head - p->tcp.dec_tail;
	void *first = p->part_pkt[0];
	uint16_t off = II_ETH_HDR_LEN + PB_IP4_HDR_LEN(first) + PB_TCP_HDR_LEN(first) * 4 + p->tcp.inc_head;
	if (ii_pb_payload_copy(w, pb_id, off, payload, len, &copied, opaque) != IIP_ERR_OK ||
			copied != len)
		return -1;
	/* Preserve the original per-fragment delivery observations. */
	uint16_t at = 0;
	for (uint16_t i = 0; i < p->cnt; i++) {
		void *pkt = p->part_pkt[i];
		uint16_t part_len = PB_IP4_TOTAL_LEN(pkt) - PB_IP4_HDR_LEN(pkt);
		uint16_t skip = i ? 0 : PB_TCP_HDR_LEN(first) * 4 + p->tcp.inc_head;
		uint16_t n = part_len > skip ? part_len - skip : 0;
		if (n > len - at)
			n = len - at;
		if (n)
			test_record_tcp_payload(opaque, conn, payload + at, n);
		at += n;
	}
	assert(at == len);
	struct test_state *state = opaque;
	if (state->defer_payload_consumption)
		state->deferred_payload_len += len;
	else
		return iip_tcp_rxbuf_consumed(w, id, len, opaque);
	return 0;
}

static int test_backend_callback(struct iip_workspace *w, uint32_t id, uint32_t pb_id, enum test_backend_callback_type type, void *opaque)
{
	struct ii_tcp_conn *conn = &w->tcp_conns.array[id];
	struct ii_pb *p = &w->pbs.array[pb_id];
	test_event_tcp_state_set(opaque, conn, conn->state);
	switch (type) {
	case TEST_BACKEND_CONNECTED:
		conn->opaque = iip_ops_tcp_connected(w, conn, p, opaque);
		break;
	case TEST_BACKEND_ACCEPTED:
		conn->opaque = iip_ops_tcp_accepted(w, conn, p, opaque);
		break;
	case TEST_BACKEND_PAYLOAD:
		return test_backend_tcp_payload(w, id, pb_id, opaque);
	case TEST_BACKEND_CLOSE_WAIT:
		test_tcp_state_close_wait(w, conn, opaque);
		break;
	case TEST_BACKEND_CLOSED:
		iip_ops_tcp_closed(conn, conn->src_mac, ii_htonl(conn->src_ip[0]),
			ii_htons(conn->src_port), conn->dst_mac,
			ii_htonl(conn->dst_ip[0]), ii_htons(conn->dst_port),
			conn->opaque, opaque);
		break;
	case TEST_BACKEND_URGENT:
		test_event_tcp_urgent(opaque, conn, conn->opaque, p->part_pkt[0]);
		break;
	case TEST_BACKEND_FASTOPEN_REQUEST:
		test_tcp_fastopen_request(ii_htonl(conn->dst_ip[0]),
			ii_htonl(conn->src_ip[0]), conn->fastopen_cookie.buf,
			&conn->fastopen_cookie.len);
		break;
	default:
		assert(0);
	}
	return 0;
}


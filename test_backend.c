/* Included after the packet backend; bindings share the test translation unit. */

static void test_backend_tcp_connect(struct iip_workspace *w, uint32_t conn_id, void *opaque)
{
	struct test_state *state = opaque;
	II_TCP_CONN(conn_id).diffserv = state->connect_diffserv;
}

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

static bool test_backend_ipv4_tcp_input_filter(struct iip_workspace *w,
		uint32_t id, void *opaque)
{
	const uint8_t *ip = (const uint8_t *)iip_ops_pkt_get_data(
		w->pbs.array[id].part_pkt[0], opaque) + II_ETH_HDR_LEN;
	uint32_t src = ii_ntohl(ii_extract_ipv4_src_be(ip));
	uint32_t dst = ii_ntohl(ii_extract_ipv4_dst_be(ip));
	/* This fixture has no subnet mask, so directed broadcasts are not
	 * inferred from the address's last octet. true means discard. */
	bool discard = src == UINT32_MAX || dst == UINT32_MAX ||
		(dst >> 28) == 0xe;
	if (discard)
		((struct test_state *)opaque)->tcp_input_filter_rejected++;
	return discard;
}

/* Input integration owns malformed-option packets that it consumes. */
static int test_backend_ip4_option_error(void *pkt, void *opaque)
{
	struct test_state *state = opaque;
	uint16_t size = iip_ops_pkt_get_len(pkt, opaque);
	if (size < II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL ||
			ii_ntohs(iip_ops_l2_ethertype_be(pkt, opaque)) != 0x0800)
		return 0;
	uint8_t *frame = iip_ops_pkt_get_data(pkt, opaque);
	uint8_t *ip = frame + II_ETH_HDR_LEN;
	uint16_t ihl = (ip[0] & 15) * 4;
	uint16_t total = ii_ntohs(ii_read_uint16(ip + 2));
	if ((ip[0] >> 4) != 4 || ihl < 20 || total < ihl ||
			size < II_ETH_HDR_LEN + total ||
			memcmp(frame, state->local_mac, 6) ||
			ii_extract_ipv4_dst_be(ip) != state->local_ip4_be)
		return 0;
	const uint8_t *check[1] = { ip };
	uint16_t check_len[1] = { ihl };
	if (ii_csum16(check, check_len, 1, 0)) {
		iip_ops_pkt_free(pkt, opaque);
		return 1;
	}
	unsigned int pointer = 0;
	for (unsigned int at = 20; at < ihl; ) {
		if (ip[at] == 0) break;
		if (ip[at] == 1) { at++; continue; }
		if (at + 1 == ihl) { pointer = at; break; }
		if (ip[at + 1] < 2 || at + ip[at + 1] > ihl) {
			pointer = at + 1;
			break;
		}
		at += ip[at + 1];
	}
	if (!pointer) return 0;
	uint32_t src = ii_ntohl(ii_extract_ipv4_src_be(ip));
	bool error_packet = ip[9] == 1 && total > ihl &&
		(ip[ihl] == 3 || ip[ihl] == 4 || ip[ihl] == 5 ||
		 ip[ihl] == 11 || ip[ihl] == 12);
	int result = 1;
	if (!(frame[0] & 1) && (src >> 24) != 0 && (src >> 24) != 127 &&
			(src >> 28) < 0xe &&
			!(ii_ntohs(ii_read_uint16(ip + 6)) & 0x1fff) && !error_packet) {
		uint8_t icmp[II_ICMP_HDR_LEN] = { 12, 0, 0, 0, 0, 0, 0, 0 };
		icmp[4] = (uint8_t)pointer;
		const uint8_t *parts[2] = { icmp, ip };
		IIP_PKT_LEN_T lengths[2] = { sizeof(icmp), ihl + (total - ihl < 8 ? total - ihl : 8) };
		ii_write_uint16(icmp + 2, ii_htons(ii_csum16(parts, lengths, 2, 0)));
		if (ii_ipv4_send_ethernet(frame, ii_extract_ipv4_dst_be(ip),
				frame + 6, ii_extract_ipv4_src_be(ip), 1, 0,
				parts, lengths, 2, opaque) != IIP_ERR_OK)
			result = -1;
	}
	iip_ops_pkt_free(pkt, opaque);
	return result;
}

static int test_backend_udp(struct iip_workspace *w, uint32_t id, void *opaque)
{
	struct ii_pb *p = &w->pbs.array[id];
	struct test_state *state = opaque;
	if (state->udp_port_filter_enabled) {
		uint8_t quote[60 + II_UDP_HDR_LEN];
		IIP_PKT_LEN_T copied;
		uint8_t *frame = iip_ops_pkt_get_data(p->part_pkt[0], opaque);
		const uint8_t *ip = frame + II_ETH_HDR_LEN;
		uint8_t ihl = ii_extract_ipv4_hdr_len(ip);
		uint32_t src = ii_ntohl(ii_extract_ipv4_src_be(ip));
		uint32_t dst = ii_ntohl(ii_extract_ipv4_dst_be(ip));
		if (ihl < II_IPV4_HDR_LEN_MINIMAL || ihl > 60 ||
				ii_pb_payload_copy(w, id, II_ETH_HDR_LEN, quote,
					ihl + II_UDP_HDR_LEN, &copied, opaque) != IIP_ERR_OK ||
				copied != ihl + II_UDP_HDR_LEN)
			return -1;
		if (ii_read_uint16(quote + ihl + 2) != state->udp_bound_port_be) {
			/* Do not generate ICMP errors for non-unicast traffic or a
			 * reassembly whose first stored fragment is not fragment zero. */
			if ((frame[0] & 1) || src == 0 || src == UINT32_MAX ||
					(src >> 24) == 0 || (src >> 24) == 127 ||
					(src >> 28) >= 0xe || dst == UINT32_MAX ||
					(dst >> 28) >= 0xe || (ii_ntohs(ii_read_uint16(ip + 6)) & 0x1fff))
				return 0;
			uint8_t icmp[II_ICMP_HDR_LEN] = { 3, 3, 0, 0, 0, 0, 0, 0 };
			const uint8_t *parts[2] = { icmp, quote };
			IIP_PKT_LEN_T lengths[2] = { sizeof(icmp), ihl + II_UDP_HDR_LEN };
			ii_write_uint16(icmp + 2, ii_htons(ii_csum16(parts, lengths, 2, 0)));
			/* iip owns and frees the received datagram after this callback. */
			return ii_ipv4_send_ethernet(frame, ii_extract_ipv4_dst_be(ip),
					frame + 6, ii_extract_ipv4_src_be(ip), 1, 0,
					parts, lengths, 2, opaque) == IIP_ERR_OK ? 0 : -1;
		}
	}
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
	uint16_t len = p->tcp.payload_len - p->tcp.inc_head - p->tcp.dec_tail;
	void *first = p->part_pkt[0];
	/* Offset of the first delivered octet in the reassembled IPv4 payload. */
	uint32_t skip = PB_TCP_HDR_LEN(first) * 4 + p->tcp.inc_head;
	uint16_t at = 0;
	/*
	 * Each received fragment keeps its own Ethernet and IPv4 headers.  Walk
	 * the IPv4 payload of every fragment so that headers of later fragments
	 * and link-layer padding are never treated as TCP payload.  Record one
	 * observation per fragment, as the original harness did.
	 */
	for (uint16_t i = 0; i < p->cnt && at < len; i++) {
		void *pkt = p->part_pkt[i];
		const uint8_t *data = (const uint8_t *)iip_ops_pkt_get_data(pkt, opaque) +
			iip_ops_l2_hdr_len(pkt, opaque) + PB_IP4_HDR_LEN(pkt);
		uint32_t part_len = PB_IP4_TOTAL_LEN(pkt) - PB_IP4_HDR_LEN(pkt);
		uint32_t n;
		if (skip >= part_len) {
			skip -= part_len;
			continue;
		}
		n = part_len - skip;
		if (n > (uint32_t)(len - at))
			n = len - at;
		test_record_tcp_payload(opaque, conn, data + skip, (uint16_t)n);
		at += n;
		skip = 0;
	}
	if (at != len)
		return -1;
	struct test_state *state = opaque;
	if (state->defer_payload_consumption)
		state->deferred_payload_len += len;
	else
		return iip_tcp_rxbuf_consumed(w, id, len, opaque);
	return 0;
}

static int test_backend_callback(struct iip_workspace *w, uint32_t id, uint32_t pb_id, enum test_backend_callback_type type, void *opaque)
{
	struct test_state *state = opaque;
	if (state->oracle.enabled) {
		if (type == TEST_BACKEND_CONNECTED) {
			state->oracle.conn_id = id;
			state->oracle.connected++;
		}
		if (type == TEST_BACKEND_CLOSE_WAIT) state->oracle.eof++;
		if (type == TEST_BACKEND_CLOSED) state->oracle.closed++;
	}
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


/* Bind the harness route table to iip's IPv4 option hook.  An
 * application-defined route (MUST-51/52) takes precedence over a route
 * captured from a received segment (MUST-53) for the same address pair. */
static int test_backend_ipv4_opt_send(void *opaque, uint8_t proto,
		uint32_t src_ipv4_be, uint32_t *dst_ipv4_be,
		uint8_t *ipv4_opt, uint8_t *ipv4_opt_len)
{
	struct test_state *state = opaque;
	const struct test_source_route *found = NULL;
	unsigned int i;
	*ipv4_opt_len = 0;
	if (!state || proto != 6 /* tcp */)
		return 0;
	for (i = 0; i < TEST_SOURCE_ROUTE_MAX; i++) {
		const struct test_source_route *route = &state->source_routes[i];
		if (!route->active || route->local_ip4_be != src_ipv4_be ||
				route->peer_ip4_be != *dst_ipv4_be)
			continue;
		if (!found || (route->application_defined && !found->application_defined))
			found = route;
	}
	if (!found)
		return 0;
	if (found->option_len > 40 || (found->option_len & 3U))
		return -1;
	memcpy(ipv4_opt, found->option, found->option_len);
	*ipv4_opt_len = (uint8_t)found->option_len;
	*dst_ipv4_be = found->wire_dst_ip4_be;
	return 0;
}

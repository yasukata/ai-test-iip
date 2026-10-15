/* TCP Window Scale, Timestamps, and reset scenarios.
 * Included by main.c after its shared packet/backend helpers.
 */

/* Fields of a SYN,ACK sent in response to a passive open. */
struct passive_syn_ack {
	struct ii_tcp_conn *conn;
	uint32_t iss;
	uint16_t window;
	int has_ws;
	uint8_t ws_shift;
	int has_ts;
	uint32_t ts_val;
};

/*
 * Deliver a SYN from peer_port with the requested options (ws_shift < 0
 * means no Window Scale option; ts nonzero adds a Timestamps option) and
 * record the SYN,ACK.  When establish is set, complete the handshake.
 */
static int fixture_passive_open(struct fixture *f, uint16_t peer_port_be,
		int ws_shift, int ts, int establish, struct passive_syn_ack *out)
{
	struct tcp_packet_spec spec;
	void *syn_ack = NULL;
	unsigned int i;

	memset(out, 0, sizeof(*out));
	fixture_incoming_spec(f, &spec, 100, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.tcp_flags = TEST_TCP_SYN;
	spec.window = 65535;
	tcp_packet_add_mss(&spec, 1460);
	if (ws_shift >= 0) {
		uint8_t shift = (uint8_t)ws_shift;
		tcp_packet_add_option(&spec, 3, &shift, 1);
	}
	if (ts) {
		uint8_t value[8] = { 0, 0, 0x10, 0, 0, 0, 0, 0 };
		tcp_packet_add_option(&spec, 8, value, sizeof(value));
	}
	fixture_deliver(f, build_tcp_packet(&spec, &f->state));
	fixture_run_timers(f);
	for (i = 0; i < f->state.out_cnt; i++) {
		void *pkt = f->state.out[i];
		if (PB_IP4(pkt)->proto == 6 && PB_TCP_HDR_HAS_SYN(pkt) &&
				PB_TCP_HDR_HAS_ACK(pkt) &&
				PB_TCP(pkt)->dst_be == peer_port_be)
			syn_ack = pkt;
	}
	out->conn = fixture_find_peer_port(f, peer_port_be);
	if (!syn_ack || !out->conn)
		return 0;
	out->iss = ii_ntohl(PB_TCP(syn_ack)->seq_be);
	out->window = ii_ntohs(PB_TCP(syn_ack)->win_be);
	{
		uint8_t *ws = option_find(syn_ack, 3);
		uint8_t *tsopt = option_find(syn_ack, 8);
		out->has_ws = ws && ws[1] == 3;
		out->ws_shift = out->has_ws ? ws[2] : 0;
		out->has_ts = tsopt && tsopt[1] == 10;
		if (out->has_ts)
			out->ts_val = (uint32_t)tsopt[2] << 24 | (uint32_t)tsopt[3] << 16 |
				(uint32_t)tsopt[4] << 8 | tsopt[5];
	}
	free_output(&f->state);
	if (!establish)
		return 1;
	fixture_incoming_spec(f, &spec, 101, NULL, 0);
	spec.src_port_be = peer_port_be;
	spec.ack_seq = out->iss + 1;
	spec.window = 65535;
	if (ts && out->has_ts) {
		uint8_t value[8] = { 0, 0, 0x10, 1,
			(uint8_t)(out->ts_val >> 24), (uint8_t)(out->ts_val >> 16),
			(uint8_t)(out->ts_val >> 8), (uint8_t)out->ts_val };
		tcp_packet_add_option(&spec, 8, value, sizeof(value));
	}
	fixture_deliver(f, build_tcp_packet(&spec, &f->state));
	fixture_run_timers(f);
	free_output(&f->state);
	return out->conn->state == II_TCP_STATE_ESTABLISHED;
}

/*
 * RFC 7323 Section 2.2: a TCP may send the Window Scale option in a
 * SYN,ACK only if it received the option in the initial SYN.
 */
static enum result test_tcp_ws_not_offered(const char **why)
{
	struct fixture f;
	struct passive_syn_ack syn_ack;

	if (!fixture_init(&f) ||
			!fixture_passive_open(&f, ii_htons(27000), -1, 0, 0, &syn_ack))
		return RESULT_FAIL;
	if (syn_ack.has_ws) {
		*why = "SYN,ACK carried Window Scale although the SYN did not";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * RFC 7323 Sections 2.2 and 2.3: once both SYNs carry the option, every
 * window field sent after the SYN,ACK is interpreted by the peer as
 * field << (the shift announced in the SYN,ACK).  The shift announced for
 * the local receive side is chosen locally, not copied from the peer, and
 * the window it implies must not exceed what the receive buffer can hold.
 * The peer offers the maximum shift, 14, to expose a copied value.
 */
static enum result test_tcp_ws_negotiated_window(const char **why)
{
	static const uint8_t payload[1] = { 0 };
	struct fixture f;
	struct tcp_packet_spec spec;
	struct passive_syn_ack syn_ack;
	const uint16_t peer_port_be = ii_htons(27001);
	void *ack = NULL;
	uint64_t implied;
	unsigned int i;

	if (!fixture_init(&f) ||
			!fixture_passive_open(&f, peer_port_be, 14, 0, 1, &syn_ack))
		return RESULT_FAIL;
	if (!syn_ack.has_ws)
		return RESULT_PASS; /* declining window scaling is permitted */
	if (syn_ack.ws_shift > 14) {
		*why = "SYN,ACK announced a window shift larger than 14";
		return RESULT_FAIL;
	}
	fixture_incoming_spec(&f, &spec, 101, payload, sizeof(payload));
	spec.src_port_be = peer_port_be;
	spec.ack_seq = syn_ack.iss + 1;
	spec.window = 65535;
	f.state.accept_arbitrary_payload = 1;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	for (i = 0; i < 500 && !ack; i++) {
		unsigned int k;
		for (k = 0; k < f.state.out_cnt; k++) {
			void *pkt = f.state.out[k];
			if (PB_IP4(pkt)->proto == 6 && PB_TCP_HDR_HAS_ACK(pkt) &&
					PB_TCP(pkt)->dst_be == peer_port_be &&
					ii_ntohl(PB_TCP(pkt)->ack_seq_be) == 102)
				ack = pkt;
		}
		if (!ack) {
			free_output(&f.state);
			fixture_advance_ms(&f, 1);
		}
	}
	if (!ack) {
		*why = "received data was not acknowledged";
		return RESULT_FAIL;
	}
	implied = (uint64_t)ii_ntohs(PB_TCP(ack)->win_be) << syn_ack.ws_shift;
	if (implied > syn_ack.conn->buf.capacity) {
		*why = "the window implied by the announced shift exceeds the receive buffer";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/* Deliver one data octet at sequence 101 and return the ACK for it. */
static void *passive_data_ack(struct fixture *f, uint16_t peer_port_be,
		const struct passive_syn_ack *syn_ack, const uint8_t *ts_option)
{
	static const uint8_t payload[1] = { 0 };
	struct tcp_packet_spec spec;
	unsigned int i, k;

	fixture_incoming_spec(f, &spec, 101, payload, sizeof(payload));
	spec.src_port_be = peer_port_be;
	spec.ack_seq = syn_ack->iss + 1;
	spec.window = 65535;
	if (ts_option)
		tcp_packet_add_option(&spec, 8, ts_option, 8);
	f->state.accept_arbitrary_payload = 1;
	fixture_deliver(f, build_tcp_packet(&spec, &f->state));
	for (i = 0; i < 500; i++) {
		for (k = 0; k < f->state.out_cnt; k++) {
			void *pkt = f->state.out[k];
			if (PB_IP4(pkt)->proto == 6 && PB_TCP_HDR_HAS_ACK(pkt) &&
					PB_TCP(pkt)->dst_be == peer_port_be &&
					ii_ntohl(PB_TCP(pkt)->ack_seq_be) == 102)
				return pkt;
		}
		free_output(&f->state);
		fake_clock_advance_ms(&f->state, 1);
		fixture_run_timers(f);
	}
	return NULL;
}

/*
 * RFC 7323 Section 3.2: a TCP may send the Timestamps option in segments
 * other than the initial SYN only if it received the option in the initial
 * SYN for the connection.
 */
static enum result test_tcp_ts_not_offered(const char **why)
{
	struct fixture f;
	struct passive_syn_ack syn_ack;
	const uint16_t peer_port_be = ii_htons(27100);
	void *ack;

	if (!fixture_init(&f) ||
			!fixture_passive_open(&f, peer_port_be, -1, 0, 1, &syn_ack))
		return RESULT_FAIL;
	if (syn_ack.has_ts) {
		*why = "SYN,ACK carried Timestamps although the SYN did not";
		return RESULT_FAIL;
	}
	ack = passive_data_ack(&f, peer_port_be, &syn_ack, NULL);
	if (!ack) {
		*why = "received data was not acknowledged";
		return RESULT_FAIL;
	}
	if (option_find(ack, 8)) {
		*why = "a data ACK carried Timestamps although they were not negotiated";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * RFC 7323 Sections 3.2 and 4.3: once Timestamps are negotiated, every
 * non-RST segment carries the option, and an ACK for an in-order segment
 * echoes that segment's TSval in TSecr.  Declining Timestamps in the
 * SYN,ACK is permitted.
 */
static enum result test_tcp_ts_negotiated(const char **why)
{
	struct fixture f;
	struct passive_syn_ack syn_ack;
	const uint16_t peer_port_be = ii_htons(27101);
	uint8_t ts_option[8] = { 0x00, 0x00, 0x20, 0x00, 0, 0, 0, 0 };
	uint8_t *tsopt;
	void *ack;

	if (!fixture_init(&f) ||
			!fixture_passive_open(&f, peer_port_be, -1, 1, 1, &syn_ack))
		return RESULT_FAIL;
	if (!syn_ack.has_ts)
		return RESULT_PASS;
	ts_option[4] = (uint8_t)(syn_ack.ts_val >> 24);
	ts_option[5] = (uint8_t)(syn_ack.ts_val >> 16);
	ts_option[6] = (uint8_t)(syn_ack.ts_val >> 8);
	ts_option[7] = (uint8_t)syn_ack.ts_val;
	ack = passive_data_ack(&f, peer_port_be, &syn_ack, ts_option);
	if (!ack) {
		*why = "received data was not acknowledged";
		return RESULT_FAIL;
	}
	tsopt = option_find(ack, 8);
	if (!tsopt || tsopt[1] != 10) {
		*why = "a data ACK omitted Timestamps after they were negotiated";
		return RESULT_FAIL;
	}
	if (memcmp(&tsopt[6], ts_option, 4)) {
		*why = "the ACK did not echo the TSval of the acknowledged segment";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * RFC 9293 Sections 3.10.7.1 and 3.10.7.2: an ACK-bearing segment that does
 * not belong to a synchronized connection is answered with
 * <SEQ=SEG.ACK><CTL=RST> whether the port is CLOSED or in LISTEN.  The
 * test backend accepts connections on every port, so this case is chosen
 * because the required response is the same in both states.
 */
static enum result test_tcp_rst_for_stray_ack(const char **why)
{
	static const uint8_t payload[3] = { 1, 2, 3 };
	struct fixture f;
	struct tcp_packet_spec spec;
	void *rst = NULL;
	unsigned int i;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 500, payload, sizeof(payload));
	spec.src_port_be = ii_htons(28000);
	spec.dst_port_be = ii_htons(9);
	spec.ack_seq = 0x01020304U;
	spec.tcp_flags = TEST_TCP_ACK;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	for (i = 0; i < f.state.out_cnt; i++) {
		void *pkt = f.state.out[i];
		if (PB_IP4(pkt)->proto == 6 && PB_TCP(pkt)->dst_be == ii_htons(28000))
			rst = pkt;
	}
	if (!rst || !PB_TCP_HDR_HAS_RST(rst)) {
		*why = "no RST was sent for an ACK that matches no connection";
		return RESULT_FAIL;
	}
	if (PB_TCP_HDR_HAS_ACK(rst) || PB_TCP_HDR_HAS_SYN(rst) ||
			ii_ntohl(PB_TCP(rst)->seq_be) != 0x01020304U ||
			PB_TCP(rst)->src_be != ii_htons(9) || !checksum_valid(rst)) {
		*why = "the RST was not <SEQ=SEG.ACK><CTL=RST> from the addressed port";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * RFC 9293 Sections 3.10.7.1 and 3.10.7.2: an incoming RST that matches no
 * connection is discarded; no RST is sent in response to a RST.
 */
static enum result test_tcp_no_rst_for_rst(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	unsigned int i;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 500, NULL, 0);
	spec.src_port_be = ii_htons(28001);
	spec.dst_port_be = ii_htons(9);
	spec.tcp_flags = TEST_TCP_RST;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
	spec.ack_seq = 1000;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	fixture_run_timers(&f);
	for (i = 0; i < f.state.out_cnt; i++)
		if (PB_IP4(f.state.out[i])->proto == 6) {
			*why = "a segment was sent in response to a stray RST";
			return RESULT_FAIL;
		}
	return RESULT_PASS;
}


/* Test-side API adapters, pool helpers, and observations of native stack events. */

static void test_workspace_init(struct iip_workspace *w)
{
	for (uint32_t i = 0; i < II_CONF_POOL_NUM_PB; i++) w->pbs.queue[i] = i;
	for (uint32_t i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) w->tcp_conns.queue[i] = i;
	for (uint32_t i = 0; i < IIP_CONF_TCP_CONN_HT_SIZE; i++) w->tcp.conns_ht[i] = II_CONF_POOL_NUM_TCP_CONN;
}

static uint32_t test_conn_id(struct iip_workspace *w, struct ii_tcp_conn *conn)
{
	assert(conn >= w->tcp_conns.array && conn < w->tcp_conns.array + II_CONF_POOL_NUM_TCP_CONN);
	return (uint32_t)(conn - w->tcp_conns.array);
}

static struct ii_pb *test_ring_end(struct iip_workspace *w, struct ii_pb__ring *ring, unsigned int last)
{
	if (ring->head == ring->tail) return NULL;
	uint16_t slot = last ? (ring->head + II_CONF_TCP_RING_SLOT_LEN - 1) % II_CONF_TCP_RING_SLOT_LEN : ring->tail;
	assert(ring->slot[slot] < II_CONF_POOL_NUM_PB);
	return &w->pbs.array[ring->slot[slot]];
}

static void test_ring_remove(struct iip_workspace *w, struct ii_pb__ring *ring, struct ii_pb *pb)
{
	uint32_t id;
	assert(ii_pb_ring_pull(ring, &id) == IIP_ERR_OK);
	assert(&w->pbs.array[id] == pb);
}

static void test_free_pb(struct iip_workspace *w, struct ii_pb *pb, void *opaque)
{
	assert(ii_free_pb_and_pkt(w, (uint32_t)(pb - w->pbs.array), opaque) == IIP_ERR_OK);
}

static unsigned int test_fragments_pending(struct iip_workspace *w)
{
	unsigned int count = 0;
	for (unsigned int i = 0; i < II_CONF_IPV4_FRAG_ARRAY_LEN; i++) count += w->ipv4_frag[i].cnt != 0;
	return count;
}

static uint16_t test_netcsum16(uint8_t **buf, uint16_t *len, uint16_t cnt, uint16_t initial)
{
	/* The old helper accepted the checksum to exclude, rather than a sum. */
	uint32_t sum = initial ? (uint16_t)~initial : 0;
	bool high = true;
	for (uint16_t i = 0; i < cnt; i++)
		for (uint16_t j = 0; j < len[i]; j++) {
			sum += high ? (uint32_t)buf[i][j] << 8 : buf[i][j];
			high = !high;
		}
	while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
	return (uint16_t)~sum;
}

static void test_api_set_local_address(void *opaque, const uint8_t *mac,
		uint32_t ip_be)
{
	struct test_state *state = opaque;
	memcpy(state->local_mac, mac, sizeof(state->local_mac));
	state->local_ip4_be = ip_be;
}

static void test_api_conn_init(struct iip_workspace *w, struct ii_tcp_conn *conn, uint8_t *smac, uint32_t sip, uint16_t sport, uint8_t *dmac, uint32_t dip, uint16_t dport, uint8_t state, void *opaque)
{
	test_current_opaque = opaque;
	ii_ipv4_tcp_conn_init(w, test_conn_id(w, conn), smac, sip, sport, dmac, dip, dport, 0);
	conn->state = state;
	test_event_tcp_state_set(opaque, conn, state);
	test_api_set_local_address(opaque, smac, sip);
}

static void test_api_set_time(struct iip_workspace *w, void *opaque)
{
	uint32_t now[3];
	iip_ops_util_now_ns(now, opaque);
	w->now_ms = (uint32_t)((uint64_t)now[1] * 1000 + now[2] / 1000000);
}

static int test_api_arp_request(struct iip_workspace *w, uint8_t *mac, uint32_t ip, uint32_t target, void *opaque)
{
	test_api_set_local_address(opaque, mac, ip);
	return iip_arp_ethernet_request(w, mac, ip, target, opaque);
}

static uint16_t test_api_connect(struct iip_workspace *w, uint8_t *smac, uint32_t sip, uint16_t sport, uint8_t *dmac, uint32_t dip, uint16_t dport, void *opaque)
{
	test_current_opaque = opaque;
	test_api_set_time(w, opaque);
	test_api_set_local_address(opaque, smac, sip);
	int rc = iip_tcp_ipv4_ethernet_connect(w, smac, sip, sport, dmac, dip, dport, NULL, 0, NULL, 0, 0, opaque);
	return rc == 0 ? 0 : UINT16_MAX;
}

static uint16_t test_api_fast_open(struct iip_workspace *w, uint8_t *smac, uint32_t sip, uint16_t sport, uint8_t *dmac, uint32_t dip, uint16_t dport, void *pkt, uint8_t *cookie, uint8_t len, void *opaque)
{
	test_current_opaque = opaque;
	test_api_set_time(w, opaque);
	test_api_set_local_address(opaque, smac, sip);
	return iip_tcp_ipv4_ethernet_connect(w, smac, sip, sport, dmac, dip, dport, &pkt, pkt ? 1 : 0, cookie, len, 0, opaque) == 0 ? 0 : UINT16_MAX;
}

static uint16_t test_api_send(struct iip_workspace *w, struct ii_tcp_conn *conn, void *pkt, uint8_t flags, void *opaque)
{
	(void)flags;
	test_current_opaque = opaque;
	test_api_set_time(w, opaque);
	return iip_tcp_send(w, test_conn_id(w, conn), &pkt, pkt ? 1 : 0, opaque) == 0 ? 0 : UINT16_MAX;
}

static uint16_t test_api_close(struct iip_workspace *w, struct ii_tcp_conn *conn, void *opaque)
{
	test_current_opaque = opaque;
	test_api_set_time(w, opaque);
	int rc = iip_tcp_close(w, test_conn_id(w, conn), opaque);
	test_event_tcp_state_set(opaque, conn, conn->state);
	return rc == IIP_ERR_OK ? 0 : UINT16_MAX;
}

static int test_api_consumed(struct iip_workspace *w, struct ii_tcp_conn *conn, uint32_t n, void *opaque)
{
	return iip_tcp_rxbuf_consumed(w, test_conn_id(w, conn), n, opaque);
}

static void test_api_push(struct iip_workspace *w, struct ii_tcp_conn *conn, void *pkt, uint8_t syn, uint8_t ack, uint8_t fin, uint8_t rst, uint16_t flags, uint8_t *cookie, uint8_t len, void *opaque)
{
	uint16_t tcp_flags = (syn ? II_TCP_FLAG_SYN : 0) | (ack ? II_TCP_FLAG_ACK : 0) | (fin ? II_TCP_FLAG_FIN : 0) | (rst ? II_TCP_FLAG_RST : 0) | flags;
	(void)cookie; (void)len;
	uint32_t id = test_conn_id(w, conn);
	test_api_set_time(w, opaque);
	if (pkt) assert(ii_tcp_send(w, id, tcp_flags, &pkt, 1, opaque) == IIP_ERR_OK);
	else assert(ii_tcp_tx_push_control(w, id, tcp_flags) == IIP_ERR_OK);
}

static void *test_emit_queued(struct iip_workspace *w, struct ii_tcp_conn *conn, struct ii_pb *p, void *opaque)
{
	struct test_state *state = opaque;
	unsigned int before = state->out_cnt;
	test_api_set_local_address(opaque, conn->src_mac, ii_htonl(conn->src_ip[0]));
	if (ii_tcp_xmit_queued_data_one(w, test_conn_id(w, conn), (uint32_t)(p - w->pbs.array), 0, p->tcp.payload_len, opaque) != IIP_ERR_OK) return NULL;
	assert(state->out_cnt == before + 1);
	void *pkt = state->out[before];
	state->out_cnt = before;
	return pkt;
}
/* Observe native state changes and emitted packets without altering the stack. */
static void test_api_record_run_events(struct iip_workspace *w,
		const struct ii_tcp_conn *before, unsigned int first_output, void *opaque)
{
	struct test_state *state = opaque;
	for (uint32_t i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
		struct ii_tcp_conn *conn = &w->tcp_conns.array[i];
		if (before[i].state != conn->state) test_event_tcp_state_set(opaque, conn, conn->state);
		bool new_loss = !(before[i].flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED) && (conn->flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED);
		uint8_t reason = conn->retrans_cnt > before[i].retrans_cnt ? TEST_LOSS_TIMEOUT : conn->sack.cnt ? TEST_LOSS_SACK : TEST_LOSS_DUP_ACK;
		if (new_loss) test_event_loss_detected(opaque, conn, reason, before[i].cc.win, conn->cc.win, before[i].cc.ssthresh, conn->cc.ssthresh);
		if (new_loss || conn->retrans_cnt > before[i].retrans_cnt)
			for (unsigned int j = first_output; j < state->out_cnt; j++) {
				void *pkt = state->out[j];
				if (ii_ntohs(iip_ops_l2_ethertype_be(pkt, opaque)) != 0x0800 ||
					PB_IP4(pkt)->proto != 6) continue;
				uint32_t sequence = ii_ntohl(PB_TCP(pkt)->seq_be);
				uint32_t on_wire = before[i].sent_seq - before[i].acked_seq;
				if (sequence - before[i].acked_seq < on_wire &&
					(PB_TCP_PAYLOAD_LEN(pkt) || PB_TCP_HDR_HAS_SYN(pkt) || PB_TCP_HDR_HAS_FIN(pkt)) &&
					PB_IP4(pkt)->proto == 6 && PB_TCP(pkt)->src_be == ii_htons(conn->src_port) && PB_TCP(pkt)->dst_be == ii_htons(conn->dst_port))
					test_event_tcp_retransmission(opaque, conn, pkt, reason == TEST_LOSS_TIMEOUT ? TEST_RETRANS_TIMEOUT : reason == TEST_LOSS_SACK ? TEST_RETRANS_SACK : TEST_RETRANS_DUP_ACK, conn->retrans_cnt, conn->rto_ms, w->now_ms);
			}
	}
}

static uint16_t test_api_run(struct iip_workspace *w, uint8_t *mac, uint32_t ip, void **pkts, uint16_t cnt, uint32_t *next, void *opaque)
{
	struct test_state *state = opaque;
	struct ii_tcp_conn before[II_CONF_POOL_NUM_TCP_CONN];
	memcpy(before, w->tcp_conns.array, sizeof(before));
	test_api_set_local_address(opaque, mac, ip);
	test_current_opaque = opaque;
	test_api_set_time(w, opaque);
	if (w->now_ms - w->timer.prev_fast >= 200) test_event_timer(opaque, TEST_TIMER_FAST, w->now_ms);
	if (w->now_ms - w->timer.prev_slow >= 500) test_event_timer(opaque, TEST_TIMER_SLOW, w->now_ms);
	if (w->now_ms - w->timer.prev_very_slow >= 1000) test_event_timer(opaque, TEST_TIMER_VERY_SLOW, w->now_ms);
	unsigned int first_output = state->out_cnt;
	void *forwarded[TEST_PKT_MAX];
	uint16_t forwarded_count = 0;
	if (state->ip4_option_error_integration) {
		assert(cnt <= TEST_PKT_MAX);
		for (uint16_t i = 0; i < cnt; i++) {
			int handled = test_backend_ip4_option_error(pkts[i], opaque);
			assert(handled >= 0);
			if (!handled) forwarded[forwarded_count++] = pkts[i];
		}
	}
	int rc = state->ip4_option_error_integration
		? iip_run(w, forwarded, forwarded_count, next, opaque)
		: iip_run(w, pkts, cnt, next, opaque);
	test_api_record_run_events(w, before, first_output, opaque);
	return rc == 0 ? cnt : UINT16_MAX;
}


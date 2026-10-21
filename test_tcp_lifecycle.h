/* Native OPEN/CLOSE and wire-driven teardown. Peer sequence/stream oracles
 * are separate from iip state; pool and heap counts supplement wire checks.
 * No test cleanup repairs a target leak before checking resource balance. */
#define LIFE_LOCAL_IP UINT32_C(0xc0000201)
#define LIFE_PEER_IP UINT32_C(0xc6336402)

struct life_peer {
    struct ii_tcp_conn *conn;
    uint16_t local_port, remote_port;
    uint32_t local_next, peer_next;
};
struct life_baseline { uint64_t backings, clones; };

static int life_init(struct fixture *f, struct life_baseline *base)
{
    memset(f, 0, sizeof(*f));
    f->local_mac[0] = 2; f->peer_mac[0] = 4;
    f->ws = calloc(1, sizeof(*f->ws));
    if (!f->ws) return fixture_setup_failed("lifecycle workspace allocation failed");
    test_workspace_init(f->ws);
    f->state.use_fake_clock = 1; f->state.now_ns = UINT64_C(1000000000);
    f->state.quiet_payload = 1;
    f->state.listener_mode = 1; /* no listener: old segments cannot open a child */
    f->ws->now_ms = f->ws->timer.prev_fast = f->ws->timer.prev_slow =
        f->ws->timer.prev_very_slow = 1000;
    f->ws->tcp.iss = UINT32_C(0x12345678);
    base->backings = test_packet_backings_live;
    base->clones = test_packet_clones_live;
    return 1;
}

static int life_run(struct fixture *f, void *pkt)
{
    uint32_t next = UINT32_MAX;
    uint16_t count = pkt ? 1 : 0;
    uint16_t rc = test_api_run(f->ws, f->local_mac, ii_htonl(LIFE_LOCAL_IP),
        pkt ? &pkt : NULL, count, &next, &f->state);
    TEST_CONDITION(rc == count, "lifecycle run: expected accepted count=%u actual=%u", count, rc);
    return 1;
}
static int life_advance(struct fixture *f, uint64_t ms)
{
    fake_clock_advance_ms(&f->state, ms);
    return life_run(f, NULL);
}
static void life_spec(struct fixture *f, const struct life_peer *p,
        struct tcp_packet_spec *s, uint16_t flags, const uint8_t *data, uint16_t len)
{
    tcp_packet_spec_init(s);
    memcpy(s->src_mac, f->peer_mac, 6); memcpy(s->dst_mac, f->local_mac, 6);
    s->src_ip_be = ii_htonl(LIFE_PEER_IP); s->dst_ip_be = ii_htonl(LIFE_LOCAL_IP);
    s->src_port_be = ii_htons(p->remote_port); s->dst_port_be = ii_htons(p->local_port);
    s->seq = p->peer_next; s->ack_seq = p->local_next;
    s->tcp_flags = flags; s->payload = data; s->payload_len = len;
}
static int life_input(struct fixture *f, const struct life_peer *p, uint16_t flags)
{
    struct tcp_packet_spec s;
    life_spec(f, p, &s, flags, NULL, 0);
    return life_run(f, build_tcp_packet(&s, &f->state));
}
static unsigned life_callbacks(struct fixture *f, struct life_peer *p, unsigned type)
{
    unsigned count = 0;
    for (unsigned n = 0; n < f->state.event_count; n++) {
        struct test_event *e = &f->state.events[n];
        if (e->type == TEST_EVENT_CALLBACK && e->subtype == type && e->object == p->conn) count++;
    }
    return count;
}
static int life_tuple(void *pkt, const struct life_peer *p)
{
    return PB_IP4(pkt)->proto == 6 && PB_IP4(pkt)->src_be == ii_htonl(LIFE_LOCAL_IP) &&
        PB_IP4(pkt)->dst_be == ii_htonl(LIFE_PEER_IP) &&
        PB_TCP(pkt)->src_be == ii_htons(p->local_port) && PB_TCP(pkt)->dst_be == ii_htons(p->remote_port);
}
static int life_control(struct fixture *f, const struct life_peer *p,
        uint16_t flags, uint32_t seq, uint32_t ack)
{
    for (unsigned n = 0; n < f->state.out_cnt; n++) {
        void *pkt = f->state.out[n];
        if (life_tuple(pkt, p) && !PB_TCP_PAYLOAD_LEN(pkt) &&
            (ii_ntohs(PB_TCP(pkt)->flags) & 0x37U) == flags &&
            ii_ntohl(PB_TCP(pkt)->seq_be) == seq &&
            (!(flags & TEST_TCP_ACK) || ii_ntohl(PB_TCP(pkt)->ack_seq_be) == ack) &&
            checksum_valid(pkt) && ip4_checksum_valid(pkt)) return 1;
    }
    return 0;
}
static int life_open(struct fixture *f, struct life_peer *p,
        unsigned port, uint32_t peer_isn)
{
    memset(p, 0, sizeof(*p));
    p->local_port = 15000; p->remote_port = port; p->peer_next = peer_isn;
    TEST_CONDITION(test_api_connect(f->ws, f->local_mac, ii_htonl(LIFE_LOCAL_IP),
        ii_htons(p->local_port), f->peer_mac, ii_htonl(LIFE_PEER_IP), ii_htons(port), &f->state) == 0,
        "OPEN port=%u failed", port);
    TEST_CONDITION(life_run(f, NULL), "OPEN timers failed");
    unsigned syns = 0;
    for (unsigned n = 0; n < f->state.out_cnt; n++) {
        void *pkt = f->state.out[n];
        if (life_tuple(pkt, p) && PB_TCP_HDR_HAS_SYN(pkt) && !PB_TCP_HDR_HAS_ACK(pkt) &&
            checksum_valid(pkt) && ip4_checksum_valid(pkt)) {
            p->local_next = ii_ntohl(PB_TCP(pkt)->seq_be) + 1U; syns++;
        }
    }
    TEST_CONDITION(syns == 1, "OPEN port=%u expected one valid SYN actual=%u", port, syns);
    free_output(&f->state);
    TEST_CONDITION(life_input(f, p, TEST_TCP_SYN | TEST_TCP_ACK), "SYN+ACK input failed");
    p->peer_next++;
    for (unsigned n = 0; n < II_CONF_POOL_NUM_TCP_CONN; n++) {
        struct ii_tcp_conn *c = &f->ws->tcp_conns.array[n];
        if (c->state != II_TCP_STATE_CLOSED && c->src_port == p->local_port && c->dst_port == port) {
            TEST_CONDITION(!p->conn, "OPEN created duplicate live tuple port=%u", port);
            p->conn = c;
        }
    }
    TEST_CONDITION(p->conn && p->conn->state == II_TCP_STATE_ESTABLISHED &&
        p->conn->seq_next_expected == p->peer_next &&
        life_control(f, p, TEST_TCP_ACK, p->local_next, p->peer_next),
        "handshake port=%u did not establish with final ACK", port);
    TEST_CONDITION(life_callbacks(f, p, TEST_CALLBACK_CONNECTED) == 1 &&
        life_callbacks(f, p, TEST_CALLBACK_ACCEPTED) == 0 &&
        life_callbacks(f, p, TEST_CALLBACK_CLOSED) == 0,
        "handshake port=%u unexpected application callbacks", port);
    free_output(&f->state);
    return 1;
}
static int life_send(struct fixture *f, struct life_peer *p, uint8_t first, unsigned len)
{
    void *pkt = iip_ops_pkt_alloc(&f->state);
    uint8_t *b = iip_ops_pkt_get_data(pkt, &f->state);
    for (unsigned n = 0; n < len; n++) b[n] = first + n;
    iip_ops_pkt_set_len(pkt, len, &f->state);
    TEST_CONDITION(test_api_send(f->ws, p->conn, pkt, 0, &f->state) == 0,
        "SEND port=%u len=%u failed", p->remote_port, len);
    return life_run(f, NULL);
}
/* Validate data and FIN independently of descriptor boundaries. */
static int life_wire(struct fixture *f, const struct life_peer *p,
        uint32_t start, uint8_t first, unsigned len, int require_data, int require_fin)
{
    uint8_t seen[64] = {0};
    int fin = 0;
    assert(len <= sizeof(seen));
    for (unsigned n = 0; n < f->state.out_cnt; n++) {
        void *pkt = f->state.out[n];
        if (!life_tuple(pkt, p)) continue;
        TEST_CONDITION(checksum_valid(pkt) && ip4_checksum_valid(pkt) &&
            !PB_TCP_HDR_HAS_RST(pkt) && !PB_TCP_HDR_HAS_SYN(pkt), "wire port=%u checksum/control mismatch", p->remote_port);
        unsigned size = PB_TCP_PAYLOAD_LEN(pkt), off = ii_ntohl(PB_TCP(pkt)->seq_be) - start;
        if (size) {
            TEST_CONDITION(off <= len && size <= len - off, "wire port=%u outside sent stream off=%u len=%u", p->remote_port, off, size);
            uint8_t *data = (uint8_t *)PB_TCP(pkt) + PB_TCP_HDR_LEN(pkt)*4;
            for (unsigned j = 0; j < size; j++) {
                TEST_CONDITION(data[j] == (uint8_t)(first + off + j), "wire port=%u corrupt byte=%u", p->remote_port, off+j);
                seen[off+j] = 1;
            }
        }
        if (PB_TCP_HDR_HAS_FIN(pkt)) {
            TEST_CONDITION(off + size == len, "FIN port=%u expected seq=%u actual=%u", p->remote_port, start+len, start+off+size);
            fin = 1;
        }
    }
    if (require_data) for (unsigned n = 0; n < len; n++)
        TEST_CONDITION(seen[n], "wire port=%u missing byte=%u", p->remote_port, n);
    TEST_CONDITION(!require_fin || fin, "wire port=%u missing FIN", p->remote_port);
    return 1;
}
static int life_receive(struct fixture *f, struct life_peer *p, uint8_t first, unsigned len)
{
    struct tcp_packet_spec s;
    uint8_t data[32];
    assert(len <= sizeof(data));
    for (unsigned n = 0; n < len; n++) data[n] = first + n;
    uint64_t before = f->state.payload_byte_count;
    unsigned callbacks = life_callbacks(f, p, TEST_CALLBACK_PAYLOAD);
    f->state.next_payload = first; /* content oracle for this scripted delivery */
    life_spec(f, p, &s, TEST_TCP_ACK, data, len);
    TEST_CONDITION(life_run(f, build_tcp_packet(&s, &f->state)), "receive failed");
    p->peer_next += len;
    TEST_CONDITION(f->state.payload_byte_count == before + len &&
        f->state.next_payload == (uint8_t)(first + len) &&
        p->conn->seq_next_expected == p->peer_next &&
        life_callbacks(f, p, TEST_CALLBACK_PAYLOAD) == callbacks + 1,
        "receive port=%u expected own callback and %u ordered bytes, actual bytes=%llu",
        p->remote_port, len, (unsigned long long)(f->state.payload_byte_count-before));
    free_output(&f->state);
    return 1;
}
static int life_reset(struct fixture *f, struct life_peer *p)
{
    unsigned closed = life_callbacks(f, p, TEST_CALLBACK_CLOSED);
    TEST_CONDITION(life_input(f, p, TEST_TCP_RST | TEST_TCP_ACK), "RST input failed");
    TEST_CONDITION(p->conn->state == II_TCP_STATE_CLOSED &&
        life_callbacks(f, p, TEST_CALLBACK_CLOSED) == closed + 1,
        "RST port=%u expected CLOSED and one close callback, state=%u callbacks=%u",
        p->remote_port, p->conn->state, life_callbacks(f, p, TEST_CALLBACK_CLOSED)-closed);
    for (unsigned n = 0; n < f->state.event_count; n++) {
        struct test_event *e = &f->state.events[n];
        if (e->type == TEST_EVENT_CALLBACK && e->subtype == TEST_CALLBACK_CLOSED && e->object == p->conn)
            TEST_CONDITION(e->value[2] == 1, "RST close reason lost port=%u", p->remote_port);
    }
    TEST_CONDITION(f->state.out_cnt == 0, "RST port=%u emitted %u packets", p->remote_port, f->state.out_cnt);
    return 1;
}
static int life_balanced(struct fixture *f, struct life_baseline *base)
{
    free_output(&f->state);
    TEST_CONDITION(f->ws->pbs.used_cnt == 0 && f->ws->tcp_conns.used_cnt == 0 &&
        test_packet_backings_live == base->backings && test_packet_clones_live == base->clones,
        "teardown resources: descriptors=%u connections=%u backings=%llu (base=%llu) clones=%llu (base=%llu)",
        f->ws->pbs.used_cnt, f->ws->tcp_conns.used_cnt,
        (unsigned long long)test_packet_backings_live, (unsigned long long)base->backings,
        (unsigned long long)test_packet_clones_live, (unsigned long long)base->clones);
    return 1;
}
static int life_silent_after_close(struct fixture *f, struct life_peer *p)
{
    unsigned closed = life_callbacks(f, p, TEST_CALLBACK_CLOSED);
    uint64_t bytes = f->state.payload_byte_count;
    TEST_CONDITION(life_advance(f, 120000), "post-close timer run failed");
    TEST_CONDITION(f->state.out_cnt == 0 && f->state.payload_byte_count == bytes &&
        life_callbacks(f, p, TEST_CALLBACK_CLOSED) == closed,
        "post-close timer emitted packets or repeated callbacks");
    return 1;
}
static enum result life_result(int ok, const char **why)
{
    if (ok) return RESULT_PASS;
    *why = test_failure_detail;
    return RESULT_FAIL;
}

/* Closure with old data retained, then ACK-driven FIN and TIME-WAIT cleanup. */
static enum result test_life_close_unacked(const char **why)
{
    struct fixture f; struct life_peer p; struct life_baseline base;
    if (!life_init(&f, &base)) return RESULT_ERROR;
    TEST_REQUIRE(why, life_open(&f, &p, 21000, 10000), "close-unacked handshake failed");
    uint32_t start = p.local_next;
    TEST_REQUIRE(why, life_send(&f, &p, 0, 32) && life_wire(&f, &p, start, 0, 32, 1, 0), "initial sent data missing");
    free_output(&f.state);
    TEST_REQUIRE(why, test_api_close(f.ws, p.conn, &f.state) == 0 && life_run(&f, NULL), "CLOSE failed");
    TEST_REQUIRE(why, p.conn->state == II_TCP_STATE_FIN_WAIT1 &&
        ii_pb_ring_num_used(&p.conn->sent_ring) && life_callbacks(&f, &p, TEST_CALLBACK_CLOSED) == 0,
        "CLOSE released unacknowledged data or notified too early");
    /* The FIN may be held by the send window. Data retransmission must survive. */
    TEST_REQUIRE(why, life_wire(&f, &p, start, 0, 32, 0, 0), "CLOSE corrupted FIN sequence");
    free_output(&f.state);
    TEST_REQUIRE(why, life_advance(&f, (uint64_t)p.conn->rto_ms + 501) &&
        life_wire(&f, &p, start, 0, 32, 1, 0), "CLOSE suppressed/corrupted retransmission");
    free_output(&f.state);
    p.local_next += 32;
    TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_ACK), "data ACK failed");
    /* A FIN already transmitted may now need its own retransmission. */
    if (!life_control(&f, &p, TEST_TCP_FIN | TEST_TCP_ACK, p.local_next, p.peer_next))
        TEST_REQUIRE(why, life_advance(&f, (uint64_t)p.conn->rto_ms + 501), "FIN retransmission timer failed");
    TEST_REQUIRE(why, life_control(&f, &p, TEST_TCP_FIN | TEST_TCP_ACK, p.local_next, p.peer_next), "missing FIN after data ACK");
    free_output(&f.state);
    p.local_next++;
    TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_ACK) && p.conn->state == II_TCP_STATE_FIN_WAIT2, "FIN ACK did not enter FIN-WAIT-2");
    free_output(&f.state);
    TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_FIN | TEST_TCP_ACK), "peer FIN failed");
    p.peer_next++;
    TEST_REQUIRE(why, p.conn->state == II_TCP_STATE_TIME_WAIT &&
        life_control(&f, &p, TEST_TCP_ACK, p.local_next, p.peer_next), "peer FIN did not enter TIME-WAIT/ACK");
    free_output(&f.state);
    TEST_REQUIRE(why, life_advance(&f, IIP_CONF_TCP_MSL_SEC * 2000ULL + 1000), "TIME-WAIT expiry failed");
    TEST_REQUIRE(why, life_callbacks(&f, &p, TEST_CALLBACK_CLOSED) == 1, "TIME-WAIT expected one close callback");
    int ok = life_silent_after_close(&f, &p) && life_balanced(&f, &base);
    if (ok) free(f.ws);
    return life_result(ok, why);
}

/* Run before RTO, at its recorded deadline (input processed in that run),
 * and after independently observing one actual timeout retransmission. */
static enum result life_timer_input(const char **why, unsigned mode, int fin)
{
    struct fixture f; struct life_peer p; struct life_baseline base;
    if (!life_init(&f, &base)) return RESULT_ERROR;
    TEST_REQUIRE(why, life_open(&f, &p, 21000, 10000) && life_send(&f, &p, 0, 32) &&
        life_wire(&f, &p, p.local_next, 0, 32, 1, 0), "timer case setup failed");
    free_output(&f.state);
    uint32_t delay = p.conn->rto_expire - f.ws->now_ms;
    TEST_REQUIRE(why, delay > 1 && delay < 120000, "RTO deadline precondition: delta=%u", delay);
    if (mode == 2) {
        TEST_REQUIRE(why, life_advance(&f, (uint64_t)delay + 501) &&
            life_wire(&f, &p, p.local_next, 0, 32, 1, 0), "expected actual RTO retransmission before input");
        free_output(&f.state);
    } else fake_clock_advance_ms(&f.state, delay - (mode == 0));
    if (!fin) {
        TEST_REQUIRE(why, life_reset(&f, &p), "RST near RTO did not close cleanly");
    } else {
        TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_FIN | TEST_TCP_ACK), "FIN near RTO input failed");
        p.peer_next++;
        TEST_REQUIRE(why, p.conn->state == II_TCP_STATE_CLOSE_WAIT && f.state.close_wait.count == 1 &&
            life_callbacks(&f, &p, TEST_CALLBACK_CLOSED) == 0 && ii_pb_ring_num_used(&p.conn->sent_ring),
            "FIN near RTO prematurely freed outgoing data/notified close: state=%u", p.conn->state);
        TEST_REQUIRE(why, life_wire(&f, &p, p.local_next, 0, 32, 0, 0), "FIN near RTO emitted corrupt data");
        free_output(&f.state);
        TEST_REQUIRE(why, life_advance(&f, (uint64_t)p.conn->rto_ms + 501) &&
            life_wire(&f, &p, p.local_next, 0, 32, 1, 0), "CLOSE-WAIT lost retransmission");
        free_output(&f.state);
        p.local_next += 32;
        TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_ACK), "CLOSE-WAIT data ACK failed");
        free_output(&f.state);
        TEST_REQUIRE(why, test_api_close(f.ws, p.conn, &f.state) == 0 && life_run(&f, NULL) &&
            life_control(&f, &p, TEST_TCP_FIN | TEST_TCP_ACK, p.local_next, p.peer_next), "LAST-ACK FIN missing");
        free_output(&f.state);
        p.local_next++;
        TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_ACK) && p.conn->state == II_TCP_STATE_CLOSED &&
            life_callbacks(&f, &p, TEST_CALLBACK_CLOSED) == 1, "LAST-ACK completion failed");
        free_output(&f.state);
    }
    int ok = life_silent_after_close(&f, &p) && life_balanced(&f, &base);
    if (ok) free(f.ws);
    return life_result(ok, why);
}
static enum result test_life_rst_before_rto(const char **why) { return life_timer_input(why, 0, 0); }
static enum result test_life_rst_at_rto(const char **why) { return life_timer_input(why, 1, 0); }
static enum result test_life_rst_after_rto(const char **why) { return life_timer_input(why, 2, 0); }
static enum result test_life_fin_before_rto(const char **why) { return life_timer_input(why, 0, 1); }
static enum result test_life_fin_at_rto(const char **why) { return life_timer_input(why, 1, 1); }
static enum result test_life_fin_after_rto(const char **why) { return life_timer_input(why, 2, 1); }

static enum result test_life_rst_all_queues(const char **why)
{
    struct fixture f; struct life_peer p; struct life_baseline base;
    struct tcp_packet_spec s; const uint8_t data[] = {8,9,10,11};
    if (!life_init(&f, &base)) return RESULT_ERROR;
    TEST_REQUIRE(why, life_open(&f, &p, 21000, 10000) && life_send(&f, &p, 0, 32), "RST queue setup failed");
    free_output(&f.state);
    life_spec(&f, &p, &s, TEST_TCP_ACK, NULL, 0); s.window = 0;
    TEST_REQUIRE(why, life_run(&f, build_tcp_packet(&s, &f.state)) && life_send(&f, &p, 32, 32), "queue behind zero window failed");
    free_output(&f.state);
    life_spec(&f, &p, &s, TEST_TCP_ACK, data, sizeof(data)); s.seq += 8; s.window = 0;
    TEST_REQUIRE(why, life_run(&f, build_tcp_packet(&s, &f.state)), "queue out-of-order receive failed");
    free_output(&f.state);
    if (!ii_pb_ring_num_used(&p.conn->pending_ring)) {
        *why = "out-of-order retention unavailable; cannot exercise pending-ring cleanup";
        return RESULT_INCONCLUSIVE;
    }
    TEST_REQUIRE(why, ii_pb_ring_num_used(&p.conn->sent_ring) && ii_pb_ring_num_used(&p.conn->tx_ring), "missing sent/unsent queue precondition");
    int ok = life_reset(&f, &p);
    /* Continue resource checks even when RST wrongly emitted queued packets. */
    TEST_ACCUMULATE(ok, f.state.payload_byte_count == 0 &&
        !ii_pb_ring_num_used(&p.conn->pending_ring) && !ii_pb_ring_num_used(&p.conn->sent_ring) &&
        !ii_pb_ring_num_used(&p.conn->tx_ring) && !ii_pb_ring_num_used(&p.conn->rx_ring), "RST failed to discard queued data");
    if (!life_balanced(&f, &base)) ok = 0;
    if (!life_silent_after_close(&f, &p)) ok = 0;
    if (ok) free(f.ws);
    return life_result(ok, why);
}

static int life_graceful(struct fixture *f, struct life_peer *p)
{
    TEST_CONDITION(life_input(f, p, TEST_TCP_FIN | TEST_TCP_ACK), "peer FIN failed");
    p->peer_next++;
    TEST_CONDITION(p->conn->state == II_TCP_STATE_CLOSE_WAIT &&
        life_control(f, p, TEST_TCP_ACK, p->local_next, p->peer_next), "peer FIN ACK/state missing");
    free_output(&f->state);
    TEST_CONDITION(test_api_close(f->ws, p->conn, &f->state) == 0 && life_run(f, NULL) &&
        life_control(f, p, TEST_TCP_FIN | TEST_TCP_ACK, p->local_next, p->peer_next), "local FIN missing");
    p->local_next++; free_output(&f->state);
    TEST_CONDITION(life_input(f, p, TEST_TCP_ACK) && p->conn->state == II_TCP_STATE_CLOSED &&
        life_callbacks(f, p, TEST_CALLBACK_CLOSED) == 1, "graceful completion missing/duplicate");
    free_output(&f->state);
    return 1;
}
static enum result life_repeat(const char **why, int reset)
{
    struct fixture f; struct life_peer p; struct life_baseline base;
    if (!life_init(&f, &base)) return RESULT_ERROR;
    for (unsigned round = 0; round < 32; round++) {
        test_event_log_clear(&f.state);
        TEST_REQUIRE(why, life_open(&f, &p, 21000, 10000U + round * 0x01000000U), "repeat round=%u handshake failed", round);
        TEST_REQUIRE(why, life_receive(&f, &p, (uint8_t)(round*8), 8) && life_send(&f, &p, round, 16) &&
            life_wire(&f, &p, p.local_next, round, 16, 1, 0), "repeat round=%u data failed", round);
        free_output(&f.state);
        if (reset) TEST_REQUIRE(why, life_reset(&f, &p), "repeat round=%u reset failed", round);
        else {
            p.local_next += 16;
            TEST_REQUIRE(why, life_input(&f, &p, TEST_TCP_ACK), "repeat data ACK failed");
            free_output(&f.state);
            TEST_REQUIRE(why, life_graceful(&f, &p), "repeat round=%u graceful close failed", round);
        }
        TEST_REQUIRE(why, life_balanced(&f, &base), "repeat round=%u resources did not return to baseline", round);
        TEST_REQUIRE(why, life_advance(&f, 10) && f.state.out_cnt == 0, "repeat round=%u late output", round);
    }
    free(f.ws);
    return RESULT_PASS;
}
static enum result test_life_repeat_close(const char **why) { return life_repeat(why, 0); }
static enum result test_life_repeat_reset(const char **why) { return life_repeat(why, 1); }

static enum result life_postclose(const char **why, unsigned kind)
{
    struct fixture f; struct life_peer p; struct life_baseline base;
    struct tcp_packet_spec s; const uint8_t data[] = {0,1,2,3};
    if (!life_init(&f, &base)) return RESULT_ERROR;
    TEST_REQUIRE(why, life_open(&f, &p, 21000, 10000) && life_reset(&f, &p), "post-close setup failed");
    TEST_REQUIRE(why, life_balanced(&f, &base), "post-close resources already retained");
    for (unsigned n = 0; n < 3; n++) {
        life_spec(&f, &p, &s, TEST_TCP_ACK | (kind == 1 ? TEST_TCP_FIN : kind == 2 ? TEST_TCP_RST : 0),
            kind == 0 ? data : NULL, kind == 0 ? sizeof(data) : 0);
        TEST_REQUIRE(why, life_run(&f, build_tcp_packet(&s, &f.state)), "post-close input failed");
        TEST_REQUIRE(why, f.state.payload_byte_count == 0 && f.state.close_wait.count == 0 &&
            life_callbacks(&f, &p, TEST_CALLBACK_CLOSED) == 1 && f.ws->tcp_conns.used_cnt == 0,
            "post-close kind=%u repeat=%u resurrected context/callback/data", kind, n);
        TEST_REQUIRE(why, kind == 2 ? f.state.out_cnt == 0 :
            life_control(&f, &p, TEST_TCP_RST, p.local_next, 0), "post-close kind=%u invalid RST response", kind);
        free_output(&f.state);
    }
    int ok = life_silent_after_close(&f, &p) && life_balanced(&f, &base);
    if (ok) free(f.ws);
    return life_result(ok, why);
}
static enum result test_life_closed_data(const char **why) { return life_postclose(why, 0); }
static enum result test_life_closed_fin(const char **why) { return life_postclose(why, 1); }
static enum result test_life_closed_rst(const char **why) { return life_postclose(why, 2); }

static enum result life_reuse(const char **why, unsigned kind)
{
    struct fixture f; struct life_peer old, fresh; struct life_baseline base;
    struct tcp_packet_spec stale; const uint8_t data[] = {200,201,202,203};
    if (!life_init(&f, &base)) return RESULT_ERROR;
    TEST_REQUIRE(why, life_open(&f, &old, 21000, 10000), "old connection setup failed");
    life_spec(&f, &old, &stale, TEST_TCP_ACK | (kind == 1 ? TEST_TCP_FIN : kind == 2 ? TEST_TCP_RST : 0),
        kind == 0 ? data : NULL, kind == 0 ? sizeof(data) : 0);
    TEST_REQUIRE(why, life_reset(&f, &old) && life_balanced(&f, &base) && life_advance(&f, 3000), "old teardown failed");
    test_event_log_clear(&f.state);
    TEST_REQUIRE(why, life_open(&f, &fresh, 21000, 0x02000000), "reused tuple could not establish");
    if (fresh.conn != old.conn) {
        *why = "allocator did not reuse the freed slot; same-context reuse not established";
        return RESULT_INCONCLUSIVE;
    }
    uint32_t start = fresh.local_next;
    TEST_REQUIRE(why, life_send(&f, &fresh, 40, 32) && life_wire(&f, &fresh, start, 40, 32, 1, 0), "new stream setup failed");
    free_output(&f.state);
    for (unsigned n = 0; n < 2; n++) {
        TEST_REQUIRE(why, life_run(&f, build_tcp_packet(&stale, &f.state)), "old incarnation input failed");
        TEST_REQUIRE(why, fresh.conn->state == II_TCP_STATE_ESTABLISHED &&
            fresh.conn->seq_next_expected == fresh.peer_next && fresh.conn->acked_seq == start &&
            f.state.payload_byte_count == 0 && f.state.close_wait.count == 0 &&
            life_callbacks(&f, &fresh, TEST_CALLBACK_CLOSED) == 0,
            "old incarnation kind=%u corrupted new connection", kind);
        /* A challenge/duplicate ACK is allowed; old data/FIN/RST is not. */
        TEST_REQUIRE(why, life_wire(&f, &fresh, start, 40, 32, 0, 0), "old incarnation caused invalid output");
        free_output(&f.state);
    }
    TEST_REQUIRE(why, life_advance(&f, (uint64_t)fresh.conn->rto_ms + 501) &&
        life_wire(&f, &fresh, start, 40, 32, 1, 0), "old packet released/corrupted new retransmission buffers");
    free_output(&f.state);
    fresh.local_next += 32;
    TEST_REQUIRE(why, life_input(&f, &fresh, TEST_TCP_ACK), "new ACK failed");
    free_output(&f.state);
    TEST_REQUIRE(why, life_receive(&f, &fresh, 0, 8) && life_reset(&f, &fresh), "new connection failed positive control/cleanup");
    int ok = life_silent_after_close(&f, &fresh) && life_balanced(&f, &base);
    if (ok) free(f.ws);
    return life_result(ok, why);
}
static enum result test_life_reuse_data(const char **why) { return life_reuse(why, 0); }
static enum result test_life_reuse_fin(const char **why) { return life_reuse(why, 1); }
static enum result test_life_reuse_rst(const char **why) { return life_reuse(why, 2); }
static enum result test_life_reuse_ack(const char **why) { return life_reuse(why, 3); }

static enum result test_life_multiple(const char **why)
{
    struct fixture f; struct life_peer p[3]; struct life_baseline base;
    if (!life_init(&f, &base)) return RESULT_ERROR;
    for (unsigned n = 0; n < 3; n++) {
        TEST_REQUIRE(why, life_open(&f, &p[n], 21000+n, 10000+n*1000) &&
            life_send(&f, &p[n], n*64, 32) && life_wire(&f, &p[n], p[n].local_next, n*64, 32, 1, 0), "multi connection=%u setup failed", n);
        free_output(&f.state);
    }
    TEST_REQUIRE(why, f.ws->tcp_conns.used_cnt == 3 &&
        life_receive(&f, &p[1], 64, 8) && life_receive(&f, &p[0], 0, 8) && life_receive(&f, &p[2], 128, 8), "multi receive demultiplexing failed");
    /* Abort B with outstanding data. A and C must retain their own bytes. */
    TEST_REQUIRE(why, life_reset(&f, &p[1]) && f.ws->tcp_conns.used_cnt == 2, "multi reset removed wrong number of contexts");
    TEST_REQUIRE(why, life_advance(&f, 4000) &&
        life_wire(&f, &p[0], p[0].local_next, 0, 32, 1, 0) &&
        life_wire(&f, &p[2], p[2].local_next, 128, 32, 1, 0), "multi reset corrupted other retransmissions");
    for (unsigned n = 0; n < f.state.out_cnt; n++)
        TEST_REQUIRE(why, !life_tuple(f.state.out[n], &p[1]), "closed connection B retransmitted");
    free_output(&f.state);
    for (unsigned n = 0; n < 3; n += 2) {
        p[n].local_next += 32;
        TEST_REQUIRE(why, life_input(&f, &p[n], TEST_TCP_ACK), "multi ACK failed");
        free_output(&f.state);
        TEST_REQUIRE(why, life_receive(&f, &p[n], n*64+8, 8) && life_reset(&f, &p[n]), "multi survivor failed positive control/close");
    }
    int ok = life_silent_after_close(&f, &p[1]) && life_balanced(&f, &base);
    for (unsigned n = 0; n < 3; n++)
        TEST_ACCUMULATE(ok, life_callbacks(&f, &p[n], TEST_CALLBACK_CLOSED) == 1,
            "multi connection=%u repeated/missing close callback", n);
    if (ok) free(f.ws);
    return life_result(ok, why);
}

static enum result test_life_application_abort(const char **why)
{
    /* The public API exports CLOSE but no ABORT. Internal close flags or a
     * synthetic incoming RST would not test application-initiated abort. */
    (void)why;
    *why = "native application ABORT API/binding is unavailable; abort during transmission is not established";
    return RESULT_INCONCLUSIVE;
}

static enum result test_life_connection_exhaustion(const char **why)
{
    struct fixture f; struct life_baseline base;
    struct life_peer peers[II_CONF_POOL_NUM_TCP_CONN], replacement;
    if (!life_init(&f, &base)) return RESULT_ERROR;
    for (unsigned n = 0; n < II_CONF_POOL_NUM_TCP_CONN; n++) {
        test_event_log_clear(&f.state);
        TEST_REQUIRE(why, life_open(&f, &peers[n], 21000+n, 10000+n*1000),
            "connection capacity setup failed at %u", n);
    }
    TEST_REQUIRE(why, f.ws->tcp_conns.used_cnt == II_CONF_POOL_NUM_TCP_CONN,
        "connection pool not full");
    TEST_REQUIRE(why, test_api_connect(f.ws, f.local_mac, ii_htonl(LIFE_LOCAL_IP),
        ii_htons(15000), f.peer_mac, ii_htonl(LIFE_PEER_IP), ii_htons(22000), &f.state) != 0 &&
        f.ws->tcp_conns.used_cnt == II_CONF_POOL_NUM_TCP_CONN && f.state.out_cnt == 0,
        "exhausted OPEN did not fail atomically");
    test_event_log_clear(&f.state);
    TEST_REQUIRE(why, life_reset(&f, &peers[0]), "could not release full-pool connection");
    test_event_log_clear(&f.state);
    TEST_REQUIRE(why, life_open(&f, &replacement, 22000, 900000) &&
        life_receive(&f, &replacement, 0, 8), "connection capacity did not recover");
    TEST_REQUIRE(why, life_reset(&f, &replacement), "replacement cleanup failed");
    for (unsigned n = 1; n < II_CONF_POOL_NUM_TCP_CONN; n++) {
        test_event_log_clear(&f.state);
        TEST_REQUIRE(why, peers[n].conn->state == II_TCP_STATE_ESTABLISHED &&
            life_receive(&f, &peers[n], (uint8_t)n, 8) && life_reset(&f, &peers[n]),
            "pool exhaustion corrupted survivor %u", n);
    }
    int ok = life_silent_after_close(&f, &peers[II_CONF_POOL_NUM_TCP_CONN-1]) && life_balanced(&f, &base);
    if (ok) free(f.ws);
    return life_result(ok, why);
}

static enum result test_life_descriptor_exhaustion(const char **why)
{
    struct fixture f; struct life_baseline base; struct life_peer fresh;
    uint32_t reserved[II_CONF_POOL_NUM_PB];
    if (!life_init(&f, &base)) return RESULT_ERROR;
    /* Reserve only unused descriptors, without modifying any live connection.
     * Release exactly these reservations; never repair failed OPEN state. */
    for (unsigned n = 0; n < II_CONF_POOL_NUM_PB; n++)
        TEST_REQUIRE(why, ii_alloc_pb(&f.ws->pbs, &reserved[n]) == IIP_ERR_OK,
            "descriptor reservation failed at %u", n);
    uint16_t rc = test_api_connect(f.ws, f.local_mac, ii_htonl(LIFE_LOCAL_IP),
        ii_htons(15000), f.peer_mac, ii_htonl(LIFE_PEER_IP), ii_htons(21000), &f.state);
    unsigned retained = f.ws->tcp_conns.used_cnt;
    for (unsigned n = 0; n < II_CONF_POOL_NUM_PB; n++)
        TEST_REQUIRE(why, ii_free_pb(&f.ws->pbs, reserved[n]) == IIP_ERR_OK,
            "descriptor reservation release failed at %u", n);
    TEST_REQUIRE(why, rc != 0 && f.state.out_cnt == 0, "descriptor-exhausted OPEN unexpectedly succeeded/emitted packets");
    /* Exercise recovery even if the failed OPEN retained a connection slot. */
    test_event_log_clear(&f.state);
    TEST_REQUIRE(why, life_open(&f, &fresh, 22000, 900000) && life_receive(&f, &fresh, 0, 8) &&
        life_send(&f, &fresh, 0, 32) && life_wire(&f, &fresh, fresh.local_next, 0, 32, 1, 0),
        "descriptor availability did not restore data transfer");
    free_output(&f.state);
    TEST_REQUIRE(why, life_reset(&f, &fresh), "descriptor recovery teardown failed");
    TEST_REQUIRE(why, retained == 0, "failed OPEN leaked %u connection slots after descriptor exhaustion", retained);
    int ok = life_silent_after_close(&f, &fresh) && life_balanced(&f, &base);
    if (ok) free(f.ws);
    return life_result(ok, why);
}

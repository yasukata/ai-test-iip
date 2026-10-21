/* Phase 6: wire observations plus explicitly labelled iip state fixtures.
 * The peer oracle uses offsets into a known stream, not iip's ACK/window or
 * congestion helpers. All waits advance virtual time; no wall-clock sleeps. */
#define FLOW_MSS 32U
#define FLOW_START UINT32_C(0xfffffff0)

static int flow_init(struct fixture *f, unsigned cwnd, unsigned threshold)
{
    if (!fixture_init(f)) return 0;
    tcp_seq_sender_at(f, FLOW_START);
    f->conn->mss = FLOW_MSS;
    f->conn->cc.win = cwnd;
    f->conn->cc.ssthresh = threshold;
    f->conn->flags &= ~II_TCP_CONN_FLAGS_SACK_OK;
    f->state.quiet_payload = 1;
    return 1;
}

static void flow_ack(struct fixture *f, uint32_t seq, unsigned offset, uint16_t window)
{
    struct tcp_packet_spec s;
    fixture_incoming_spec(f, &s, seq, NULL, 0);
    s.ack_seq = FLOW_START + offset;
    s.window = window;
    fixture_deliver(f, build_tcp_packet(&s, &f->state));
}

/* Record and validate every emitted data byte, allowing retransmissions.
 * begin/end limit the allowed sequence range independently of target state. */
static int flow_wire(struct fixture *f, unsigned begin, unsigned end,
        uint8_t *seen, unsigned *bytes)
{
    *bytes = 0;
    for (unsigned i = 0; i < f->state.out_cnt; i++) {
        void *p = f->state.out[i];
        TEST_CONDITION(PB_IP4(p)->proto == 6 && ip4_checksum_valid(p) && checksum_valid(p),
            "flow: packet=%u invalid protocol/checksum", i);
        TEST_CONDITION(!PB_TCP_HDR_HAS_SYN(p) && !PB_TCP_HDR_HAS_RST(p) && !PB_TCP_HDR_HAS_FIN(p),
            "flow: unexpected control flags packet=%u", i);
        unsigned n = PB_TCP_PAYLOAD_LEN(p), off = ii_ntohl(PB_TCP(p)->seq_be) - FLOW_START;
        if (!n) continue;
        TEST_CONDITION(off >= begin && off <= end && n <= end - off,
            "flow: wire offset=%u length=%u outside [%u,%u)", off, n, begin, end);
        const uint8_t *data = (const uint8_t *)PB_TCP(p) + PB_TCP_HDR_LEN(p) * 4;
        for (unsigned j = 0; j < n; j++) {
            TEST_CONDITION(data[j] == (uint8_t)(off + j),
                "flow: corrupt byte offset=%u expected=%u actual=%u", off+j, (uint8_t)(off+j), data[j]);
            if (seen) seen[off + j] = 1;
        }
        *bytes += n;
    }
    return 1;
}

static enum result flow_send_limit(const char **why, unsigned cwnd, unsigned rwnd)
{
    struct fixture f;
    unsigned bytes, bound = (cwnd * FLOW_MSS < rwnd ? cwnd * FLOW_MSS : rwnd);
    uint8_t seen[128] = {0};
    if (!flow_init(&f, cwnd, 16)) return RESULT_ERROR;
    flow_ack(&f, 0, 0, rwnd);
    free_output(&f.state);
    for (unsigned n = 0; n < 4; n++)
        TEST_REQUIRE(why, tcp_seq_send(&f, n * FLOW_MSS, FLOW_MSS), "queue segment=%u", n);
    TEST_REQUIRE(why, flow_wire(&f, 0, bound, seen, &bytes) && bytes == bound,
        "send limit: expected flight=%u actual bytes=%u cwnd=%u rwnd=%u", bound, bytes, cwnd, rwnd);
    for (unsigned n = 0; n < bound; n++)
        TEST_REQUIRE(why, seen[n], "send limit: missing offset=%u", n);
    free_output(&f.state);
    fixture_advance_ms(&f, 100);
    TEST_REQUIRE(why, flow_wire(&f, 0, bound, NULL, &bytes) && bytes == 0,
        "send limit: emitted %u bytes without ACK/window update", bytes);
    return RESULT_PASS;
}
static enum result test_flow_cwnd_limit(const char **why) { return flow_send_limit(why, 2, 256); }
static enum result test_flow_rwnd_limit(const char **why) { return flow_send_limit(why, 8, 64); }

/* RFC 9293 window-update ordering, including wraparound of SEG.SEQ.
 * Old and new SEQ are BOTH inside the advertised receive window, so the
 * stale row tests WL1 ordering, not the earlier segment acceptability gate.
 * Deferring an out-of-order ACK is legal; that row is inconclusive when the
 * stack cannot establish WL1 ahead of RCV.NXT through wire input. */
static enum result flow_window_update(const char **why, unsigned mode)
{
    struct fixture f;
    unsigned bytes;
    const uint32_t rcv = UINT32_C(0xfffffff0);
    if (!flow_init(&f, 8, 16)) return RESULT_ERROR;
    tcp_model_receive_at(&f, rcv);
    uint32_t advertised;
    if (!tcp_model_advertise_window(&f, &advertised) || advertised <= 32) {
        *why = "window ordering needs an observed receive window above 32";
        return RESULT_INCONCLUSIVE;
    }
    flow_ack(&f, rcv + (mode == 0 ? 24U : 0U), 0, 64);
    if (mode == 0 && f.conn->peer_win != 64) {
        *why = "stale-SEQ ordering not reached: stack defers the out-of-order ACK (permitted by RFC 9293)";
        return RESULT_INCONCLUSIVE;
    }
    TEST_REQUIRE(why, f.conn->peer_win == 64, "initial valid update: expected 64 actual=%u", f.conn->peer_win);
    free_output(&f.state);
    if (mode == 4) {
        /* Bring RCV.NXT to the newer SEG.SEQ before requiring processing.
         * RFC 9293 permits queuing higher-SEQ empty ACKs until this point. */
        uint8_t data[28];
        struct tcp_packet_spec s;
        for (unsigned n = 0; n < sizeof(data); n++) data[n] = n;
        fixture_incoming_spec(&f, &s, rcv, data, sizeof(data));
        s.ack_seq = FLOW_START;
        s.window = 64;
        fixture_deliver(&f, build_tcp_packet(&s, &f.state));
        TEST_REQUIRE(why, f.conn->seq_next_expected == rcv + 28U && f.state.payload_byte_count == 28,
            "newer update setup: expected ordered receive progress=28 actual=%llu",
            (unsigned long long)f.state.payload_byte_count);
        free_output(&f.state);
    }
    /* stale SEQ; future ACK; stale ACK; same SEQ/ACK; newer SEQ */
    static const unsigned seq_off[] = {16, 0, 0, 0, 28};
    static const unsigned ack_off[] = {0, 1, UINT32_MAX, 0, 0};
    flow_ack(&f, rcv + seq_off[mode], ack_off[mode], 128);
    free_output(&f.state);
    for (unsigned n = 0; n < 4; n++)
        TEST_REQUIRE(why, tcp_seq_send(&f, n * FLOW_MSS, FLOW_MSS), "update queue segment=%u", n);
    unsigned expected = mode < 3 ? 64 : 128;
    TEST_REQUIRE(why, flow_wire(&f, 0, expected, NULL, &bytes) && bytes == expected &&
        f.conn->peer_win == expected && f.conn->acked_seq == FLOW_START,
        "window update row=%u expected window/flight=%u actual window=%u bytes=%u UNA=%08x",
        mode, expected, f.conn->peer_win, bytes, f.conn->acked_seq);
    return RESULT_PASS;
}
static enum result test_flow_update_stale_seq(const char **why) { return flow_window_update(why, 0); }
static enum result test_flow_update_future_ack(const char **why) { return flow_window_update(why, 1); }
static enum result test_flow_update_stale_ack(const char **why) { return flow_window_update(why, 2); }
static enum result test_flow_update_equal(const char **why) { return flow_window_update(why, 3); }
static enum result test_flow_update_new_seq(const char **why) { return flow_window_update(why, 4); }

static enum result test_flow_probe_reopen(const char **why)
{
    struct fixture f;
    unsigned bytes, probes = 0;
    uint8_t seen[32] = {0};
    if (!flow_init(&f, 8, 16)) return RESULT_ERROR;
    flow_ack(&f, 0, 0, 0);
    free_output(&f.state);
    TEST_REQUIRE(why, tcp_seq_send(&f, 0, FLOW_MSS), "queue zero-window data");
    /* Receiver's first reopening update is lost: keep replying window=0
     * until a second probe, then the repeated advertisement reaches sender. */
    for (unsigned elapsed = 0; elapsed <= 120000 && probes < 2; elapsed += 100) {
        TEST_REQUIRE(why, flow_wire(&f, 0, 1, NULL, &bytes), "zero-window probe bytes/sequence/checksum");
        if (bytes) {
            probes++;
            free_output(&f.state);
            flow_ack(&f, 0, 0, 0);
        }
        free_output(&f.state);
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_ESTABLISHED && f.conn->acked_seq == FLOW_START,
            "zero-window response closed connection or released unacknowledged data");
        fixture_advance_ms(&f, 100);
    }
    TEST_REQUIRE(why, probes == 2, "expected repeated zero-window probes, observed=%u", probes);
    free_output(&f.state);
    flow_ack(&f, 0, 0, 64);
    for (unsigned ms = 0; ms < 1000; ms += 100) {
        TEST_REQUIRE(why, flow_wire(&f, 0, FLOW_MSS, seen, &bytes), "reopen wire mismatch");
        free_output(&f.state);
        fixture_advance_ms(&f, 100);
    }
    for (unsigned n = 0; n < FLOW_MSS; n++)
        TEST_REQUIRE(why, seen[n], "reopened window: missing queued offset=%u", n);
    flow_ack(&f, 0, FLOW_MSS, 64);
    TEST_REQUIRE(why, !ii_pb_ring_num_used(&f.conn->sent_ring) && !ii_pb_ring_num_used(&f.conn->tx_ring),
        "reopen cumulative ACK did not release all data");
    free_output(&f.state);
    fixture_advance_ms(&f, 4000);
    TEST_REQUIRE(why, flow_wire(&f, 0, FLOW_MSS, NULL, &bytes) && bytes == 0,
        "acknowledged probe data retransmitted: bytes=%u", bytes);
    return RESULT_PASS;
}

/* Read the most recent real ACK; no test-side invocation of the window
 * calculation. Requiring an exact value here selects the unscaled iip
 * capacity/consumption profile, rather than every legal receiver policy. */
static int flow_window_is(struct fixture *f, unsigned ack, unsigned expected)
{
    int found = 0;
    unsigned actual = UINT32_MAX;
    for (unsigned i = 0; i < f->state.out_cnt; i++) {
        void *p = f->state.out[i];
        if (PB_IP4(p)->proto == 6 && PB_TCP_HDR_HAS_ACK(p) &&
            ii_ntohl(PB_TCP(p)->ack_seq_be) == ack && checksum_valid(p) && ip4_checksum_valid(p)) {
            found = 1;
            actual = ii_ntohs(PB_TCP(p)->win_be);
        }
    }
    TEST_CONDITION(found && actual == expected,
        "receive advertisement: ACK=%u expected window=%u actual=%u found=%d", ack, expected, actual, found);
    return 1;
}

static int flow_fill_receiver(struct fixture *f)
{
    if (!flow_init(f, 8, 16)) return 0;
    f->conn->buf.capacity = 64;
    f->conn->mss = 64;
    f->state.defer_payload_consumption = 1;
    uint32_t window;
    TEST_CONDITION(tcp_model_advertise_window(f, &window) && window == 64,
        "receiver setup: missing 64-byte advertisement");
    for (unsigned at = 0; at < 64; at += 16) {
        uint8_t data[16];
        struct tcp_packet_spec s;
        for (unsigned j = 0; j < sizeof(data); j++) data[j] = at + j;
        fixture_incoming_spec(f, &s, at, data, sizeof(data));
        fixture_deliver(f, build_tcp_packet(&s, &f->state));
        fixture_advance_ms(f, 499);
        TEST_CONDITION(flow_window_is(f, at + 16, 64 - at - 16), "receive fill offset=%u", at);
        TEST_CONDITION(f->state.payload_byte_count == at + 16 && f->conn->buf.used == at + 16,
            "receive accounting: offset=%u delivered=%llu used=%u", at,
            (unsigned long long)f->state.payload_byte_count, f->conn->buf.used);
        free_output(&f->state);
    }
    return 1;
}

static enum result test_flow_receive_exhaustion(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec s;
    uint8_t data[32];
    if (!flow_fill_receiver(&f)) { *why = test_failure_detail; return RESULT_FAIL; }
    for (unsigned n = 0; n < sizeof(data); n++) data[n] = 64 + n;
    for (unsigned n = 0; n < 3; n++) {
        fixture_incoming_spec(&f, &s, 64, data, 1);
        fixture_deliver(&f, build_tcp_packet(&s, &f.state));
        TEST_REQUIRE(why, f.state.payload_byte_count == 64 && f.conn->buf.used == 64 &&
            f.conn->seq_next_expected == 64, "exhausted receiver accepted probe=%u", n);
        free_output(&f.state);
    }
    TEST_REQUIRE(why, test_api_consumed(f.ws, f.conn, 32, &f.state) == 0, "consume 32 failed");
    fixture_run_timers(&f);
    TEST_REQUIRE(why, flow_window_is(&f, 64, 32), "consumption did not advertise reopened capacity");
    free_output(&f.state);
    fixture_incoming_spec(&f, &s, 64, data, sizeof(data));
    fixture_deliver(&f, build_tcp_packet(&s, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 96 && f.state.next_payload == 96 &&
        f.conn->buf.used == 64, "reopened receiver: expected ordered 96 bytes and used=64, actual=%llu/%u",
        (unsigned long long)f.state.payload_byte_count, f.conn->buf.used);
    return RESULT_PASS;
}

static enum result test_flow_receiver_sws(const char **why)
{
    struct fixture f;
    if (!flow_fill_receiver(&f)) { *why = test_failure_detail; return RESULT_FAIL; }
    for (unsigned n = 1; n <= 32; n++) {
        TEST_REQUIRE(why, test_api_consumed(f.ws, f.conn, 1, &f.state) == 0, "consume byte=%u failed", n);
        fixture_run_timers(&f);
        if (n < 32) {
            for (unsigned i = 0; i < f.state.out_cnt; i++)
                TEST_REQUIRE(why, ii_ntohs(PB_TCP(f.state.out[i])->win_be) == 0,
                    "SWS: window reopened after only %u consumed bytes (threshold=32)", n);
        } else TEST_REQUIRE(why, flow_window_is(&f, 64, 32), "SWS exact half-buffer threshold failed");
        free_output(&f.state);
    }
    return RESULT_PASS;
}

static enum result test_flow_advertised_boundaries(const char **why)
{
    static const uint32_t capacities[] = {0, 1, 32767, 32768, 65534, 65535, 65536, UINT32_MAX};
    for (unsigned n = 0; n < sizeof(capacities)/sizeof(capacities[0]); n++) {
        struct fixture f;
        uint32_t actual = UINT32_MAX, expected = capacities[n] < 65535 ? capacities[n] : 65535;
        if (!flow_init(&f, 8, 16)) return RESULT_ERROR;
        f.conn->buf.capacity = capacities[n];
        TEST_REQUIRE(why, tcp_model_advertise_window(&f, &actual) && actual == expected,
            "unscaled advertisement: capacity=%u expected=%u actual=%u", capacities[n], expected, actual);
        free(f.ws);
    }
    return RESULT_PASS;
}

static enum result test_flow_delayed_ack_pair(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec s;
    uint8_t data[64];
    if (!flow_init(&f, 8, 16)) return RESULT_ERROR;
    f.conn->mss = 64;
    /* Full receive segments for the selected 1500-byte path, independently
     * of the peer's advertised send MSS (which governs OUR transmissions). */
    uint8_t full[1460];
    for (unsigned k = 0; k < 2; k++) {
        for (unsigned j = 0; j < sizeof(full); j++) full[j] = (uint8_t)(k * sizeof(full) + j);
        fixture_incoming_spec(&f, &s, k * sizeof(full), full, sizeof(full));
        fixture_deliver(&f, build_tcp_packet(&s, &f.state));
    }
    /* Immediate ACKs also satisfy the every-second-full-segment recommendation. */
    TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_ACK, FLOW_START, 2920),
        "second full segment: missing cumulative ACK=2920");
    TEST_REQUIRE(why, f.state.payload_byte_count == 2920, "full segment delivery count mismatch");
    free_output(&f.state);
    for (unsigned j = 0; j < sizeof(data); j++) data[j] = (uint8_t)(2920 + j);
    fixture_incoming_spec(&f, &s, 2920, data, sizeof(data));
    fixture_deliver(&f, build_tcp_packet(&s, &f.state));
    for (unsigned ms = 0; ms < 500; ms++) {
        for (unsigned i = 0; i < f.state.out_cnt; i++) {
            void *p = f.state.out[i];
            if (PB_TCP_HDR_HAS_ACK(p) && ii_ntohl(PB_TCP(p)->ack_seq_be) == 2984 &&
                checksum_valid(p) && ip4_checksum_valid(p)) return RESULT_PASS;
        }
        free_output(&f.state);
        if (ms < 499) fixture_advance_ms(&f, 1);
    }
    *why = "tail segment was not ACKed before 500 ms";
    return RESULT_FAIL;
}

static enum result test_flow_nagle_full_segment(const char **why)
{
    struct fixture f;
    unsigned bytes;
    if (!flow_init(&f, 8, 16)) return RESULT_ERROR;
    IIP_EX_TCP_SET_NAGLE_DISABLED(f.ws, f.conn, 0, &f.state);
    TEST_REQUIRE(why, tcp_seq_send(&f, 0, 1), "Nagle initial write failed");
    TEST_REQUIRE(why, flow_wire(&f, 0, 1, NULL, &bytes) && bytes == 1, "Nagle initial byte missing");
    free_output(&f.state);
    TEST_REQUIRE(why, tcp_seq_send(&f, 1, FLOW_MSS), "Nagle full-MSS write failed");
    TEST_REQUIRE(why, flow_wire(&f, 1, 1 + FLOW_MSS, NULL, &bytes) && bytes == FLOW_MSS,
        "Nagle held full segment behind unacknowledged byte: emitted=%u", bytes);
    free_output(&f.state);
    TEST_REQUIRE(why, tcp_seq_send(&f, 1 + FLOW_MSS, 1), "Nagle tail write failed");
    TEST_REQUIRE(why, f.state.out_cnt == 0, "Nagle sent small tail while earlier data unacknowledged");
    flow_ack(&f, 0, 1 + FLOW_MSS, 65535);
    TEST_REQUIRE(why, flow_wire(&f, 1 + FLOW_MSS, 2 + FLOW_MSS, NULL, &bytes) && bytes == 1,
        "Nagle failed to release tail on cumulative ACK");
    return RESULT_PASS;
}

/* Growth is deliberately a selected classic-iip profile: conservative
 * alternatives are not rejected as mandatory RFC violations. */
static enum result test_flow_slow_start(const char **why)
{
    struct fixture f;
    unsigned bytes;
    if (!flow_init(&f, 1, 8)) return RESULT_ERROR;
    for (unsigned n = 0; n < 3; n++)
        TEST_REQUIRE(why, tcp_seq_send(&f, n * FLOW_MSS, FLOW_MSS), "SS queue failed");
    TEST_REQUIRE(why, flow_wire(&f, 0, FLOW_MSS, NULL, &bytes) && bytes == FLOW_MSS,
        "SS initial flight expected=32 actual=%u", bytes);
    free_output(&f.state);
    flow_ack(&f, 0, FLOW_MSS, 65535);
    TEST_REQUIRE(why, flow_wire(&f, FLOW_MSS, 3 * FLOW_MSS, NULL, &bytes) && bytes == 2 * FLOW_MSS &&
        f.conn->cc.win == 2, "SS full-MSS ACK expected cwnd=2 flight=64 actual=%u/%u", f.conn->cc.win, bytes);
    return RESULT_PASS;
}

static enum result test_flow_congestion_avoidance(const char **why)
{
    struct fixture f;
    unsigned offset = 0, bytes;
    if (!flow_init(&f, 4, 2)) return RESULT_ERROR;
    for (unsigned round = 0; round < 4; round++) {
        unsigned flight = 4 + round; /* independent one-MSS-per-flight profile */
        unsigned begin = offset;
        for (unsigned n = 0; n < flight; n++, offset += FLOW_MSS)
            TEST_REQUIRE(why, tcp_seq_send(&f, offset, FLOW_MSS), "CA queue round=%u", round);
        TEST_REQUIRE(why, flow_wire(&f, begin, offset, NULL, &bytes) && bytes == flight * FLOW_MSS,
            "CA round=%u missing flight: expected=%u actual=%u", round, flight * FLOW_MSS, bytes);
        free_output(&f.state);
        /* One cumulative ACK per full flight also exercises byte counting. */
        flow_ack(&f, 0, offset, 65535);
        TEST_REQUIRE(why, f.conn->cc.win == flight + 1 && !ii_pb_ring_num_used(&f.conn->sent_ring),
            "CA round=%u expected cwnd=%u actual=%u", round, flight + 1, f.conn->cc.win);
        free_output(&f.state);
    }
    return RESULT_PASS;
}

static int flow_loss_setup(struct fixture *f)
{
    unsigned bytes;
    uint8_t seen[256] = {0};
    if (!flow_init(f, 8, 16)) return 0;
    /* Four writes split into eight wire segments. The default descriptor
     * ring holds only seven writes; do not mistake that resource limit for
     * congestion control. */
    for (unsigned n = 0; n < 4; n++)
        TEST_CONDITION(tcp_seq_send(f, n * 2 * FLOW_MSS, 2 * FLOW_MSS), "loss setup queue=%u", n);
    TEST_CONDITION(flow_wire(f, 0, 256, seen, &bytes) && bytes == 256,
        "loss setup expected flight=256 actual=%u", bytes);
    for (unsigned n = 0; n < sizeof(seen); n++)
        TEST_CONDITION(seen[n], "loss setup missing byte=%u", n);
    free_output(&f->state);
    return 1;
}

static enum result test_flow_fast_retransmit(const char **why)
{
    struct fixture f;
    unsigned bytes;
    if (!flow_loss_setup(&f)) { *why = test_failure_detail; return RESULT_FAIL; }
    for (unsigned n = 1; n <= 3; n++) {
        flow_ack(&f, 0, 0, 65535);
        TEST_REQUIRE(why, flow_wire(&f, 0, FLOW_MSS, NULL, &bytes), "fast retransmit corrupt range");
        TEST_REQUIRE(why, bytes == (n == 3 ? FLOW_MSS : 0),
            "duplicate ACK=%u expected retransmit bytes=%u actual=%u", n, n == 3 ? FLOW_MSS : 0, bytes);
        free_output(&f.state);
    }
    TEST_REQUIRE(why, f.conn->cc.ssthresh <= 4 && f.conn->cc.win <= 7,
        "fast loss response exceeds FlightSize/2+3: cwnd=%u ssthresh=%u", f.conn->cc.win, f.conn->cc.ssthresh);
    /* No Reno cwnd inflation is required: iip uses conservative recovery. */
    flow_ack(&f, 0, 256, 65535);
    TEST_REQUIRE(why, !ii_pb_ring_num_used(&f.conn->sent_ring), "full recovery ACK retained buffers");
    return RESULT_PASS;
}

static enum result test_flow_rto_response(const char **why)
{
    struct fixture f;
    unsigned bytes;
    if (!flow_loss_setup(&f)) { *why = test_failure_detail; return RESULT_FAIL; }
    uint32_t rto = f.conn->rto_ms;
    fixture_advance_ms(&f, (uint64_t)rto + 1);
    TEST_REQUIRE(why, flow_wire(&f, 0, FLOW_MSS, NULL, &bytes) && bytes == FLOW_MSS &&
        f.conn->cc.win <= 1 && f.conn->cc.ssthresh <= 4,
        "RTO flight=256: expected retransmit=32 cwnd<=1 ssthresh<=4; actual=%u/%u/%u",
        bytes, f.conn->cc.win, f.conn->cc.ssthresh);
    free_output(&f.state);
    fixture_advance_ms(&f, 100);
    TEST_REQUIRE(why, flow_wire(&f, 0, FLOW_MSS, NULL, &bytes) && bytes == 0,
        "RTO recovery burst before ACK: bytes=%u", bytes);
    return RESULT_PASS;
}

static enum result flow_loss_recovery(const char **why, int multiple)
{
    struct fixture f;
    uint8_t seen[288] = {0};
    unsigned bytes, ack = 0;
    if (!flow_loss_setup(&f)) { *why = test_failure_detail; return RESULT_FAIL; }
    /* Independent receiving peer retains all but segment 0 and optionally 3.
     * Duplicate cumulative ACKs represent later out-of-order arrivals. */
    for (unsigned n = FLOW_MSS; n < 256; n++)
        if (!multiple || n < 96 || n >= 128) seen[n] = 1;
    for (unsigned n = 0; n < 3; n++) flow_ack(&f, 0, 0, 65535);
    for (unsigned elapsed = 0; elapsed <= 20000 && ack < 256; elapsed += 100) {
        TEST_REQUIRE(why, flow_wire(&f, 0, 256, seen, &bytes), "loss recovery emitted corrupt/unsent bytes");
        free_output(&f.state);
        if (bytes) {
            while (ack < 256 && seen[ack]) ack++;
            flow_ack(&f, 0, ack, 65535);
        }
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_ESTABLISHED,
            "loss recovery closed: multiple=%d ack=%u", multiple, ack);
        fixture_advance_ms(&f, 100);
    }
    TEST_REQUIRE(why, ack == 256 && f.conn->acked_seq == FLOW_START + 256 &&
        !ii_pb_ring_num_used(&f.conn->sent_ring),
        "loss recovery stalled: multiple=%d peer ACK=%u UNA=%08x", multiple, ack, f.conn->acked_seq);
    free_output(&f.state);
    TEST_REQUIRE(why, tcp_seq_send(&f, 256, FLOW_MSS), "post-recovery queue failed");
    TEST_REQUIRE(why, flow_wire(&f, 256, 288, seen, &bytes) && bytes == FLOW_MSS,
        "post-recovery new data did not progress: bytes=%u", bytes);
    flow_ack(&f, 0, 288, 65535);
    TEST_REQUIRE(why, !ii_pb_ring_num_used(&f.conn->sent_ring) && !ii_pb_ring_num_used(&f.conn->tx_ring),
        "post-recovery buffers retained after final ACK");
    return RESULT_PASS;
}
static enum result test_flow_single_loss_recovery(const char **why) { return flow_loss_recovery(why, 0); }
static enum result test_flow_multiple_loss_recovery(const char **why) { return flow_loss_recovery(why, 1); }

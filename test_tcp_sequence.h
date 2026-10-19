/* RFC 9293 3.4/3.10.7.4 and RFC 2018. Offsets into short known byte
 * streams are the oracle; no target sequence comparator is used. Every
 * registered case has a fixed starting sequence and deterministic inputs. */
static void tcp_seq_sender_at(struct fixture *f, uint32_t start)
{
    fixture_prepare_sender(f);
    f->conn->iss = start - 1U;
    f->conn->seq = f->conn->sent_seq = f->conn->acked_seq = start;
    f->conn->mss = 8;
    f->conn->cc.win = 10;
    IIP_EX_TCP_SET_NAGLE_DISABLED(f->ws, f->conn, 1, &f->state);
}

static int tcp_seq_send(struct fixture *f, unsigned offset, unsigned len)
{
    void *p = iip_ops_pkt_alloc(&f->state);
    if (!p) return fixture_setup_failed("sequence-test payload allocation failed");
    uint8_t *bytes = iip_ops_pkt_get_data(p, &f->state);
    for (unsigned i = 0; i < len; i++) bytes[i] = (uint8_t)(offset + i);
    iip_ops_pkt_set_len(p, len, &f->state);
    if (test_api_send(f->ws, f->conn, p, 0, &f->state) != 0) return 0;
    fixture_run_timers(f);
    return 1;
}

/* Allow segmentation/retransmission of already ACKed prefixes, but require
 * every needed byte and reject unsent sequence space or corrupted content. */
static int tcp_seq_wire_range(struct fixture *f, uint32_t start,
        unsigned begin, unsigned end, unsigned total)
{
    uint32_t seen = 0;
    assert(end <= total && total <= 32);
    for (unsigned i = 0; i < f->state.out_cnt; i++) {
        void *p = f->state.out[i];
        if (PB_IP4(p)->proto != 6 || !checksum_valid(p) || !ip4_checksum_valid(p)) return 0;
        unsigned offset = ii_ntohl(PB_TCP(p)->seq_be) - start;
        unsigned len = PB_TCP_PAYLOAD_LEN(p);
        if (!len) continue;
        if (offset > total || len > total - offset || !PB_TCP_HDR_HAS_ACK(p) ||
            PB_TCP_HDR_HAS_SYN(p) || PB_TCP_HDR_HAS_RST(p) || PB_TCP_HDR_HAS_FIN(p)) return 0;
        const uint8_t *data = (uint8_t *)PB_TCP(p) + PB_TCP_HDR_LEN(p) * 4;
        for (unsigned n = 0; n < len; n++) {
            if (data[n] != (uint8_t)(offset + n)) return 0;
            seen |= UINT32_C(1) << (offset + n);
        }
    }
    for (unsigned n = begin; n < end; n++) if (!(seen & (UINT32_C(1) << n))) return 0;
    return 1;
}

static int tcp_seq_wire_bytes(struct fixture *f, uint32_t start,
        unsigned begin, unsigned end)
{ return tcp_seq_wire_range(f, start, begin, end, end); }

/* White-box supplement: all unacknowledged bytes still have live transmit
 * descriptors, and fully acknowledged descriptors have been released. Partial
 * descriptors may retain their acknowledged prefix (an implementation choice). */
static int tcp_seq_buffers(struct fixture *f, uint32_t start, unsigned acked, unsigned total)
{
    uint32_t covered = 0;
    struct ii_pb__ring *ring = &f->conn->sent_ring;
    unsigned count = (ring->head + II_CONF_TCP_RING_SLOT_LEN - ring->tail) % II_CONF_TCP_RING_SLOT_LEN;
    for (unsigned i = 0; i < count; i++) {
        unsigned id = ring->slot[(ring->tail + i) % II_CONF_TCP_RING_SLOT_LEN];
        if (id >= II_CONF_POOL_NUM_PB) return 0;
        struct ii_pb *p = &f->ws->pbs.array[id];
        unsigned offset = p->tcp.seq - start, len = p->tcp.payload_len;
        if (!len || offset > total || len > total - offset || offset + len <= acked) return 0;
        for (unsigned n = offset; n < offset + len; n++) covered |= UINT32_C(1) << n;
    }
    for (unsigned n = acked; n < total; n++) if (!(covered & (UINT32_C(1) << n))) return 0;
    return acked != total || count == 0;
}

static enum result tcp_seq_acks(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    /* Partial ACK, duplicate, ACK below UNA, cumulative ACK over packet
     * boundaries, final ACK. Each row independently specifies expected UNA. */
    static const struct { unsigned ack, una; const char *name; } steps[] = {
        { UINT32_MAX, 0, "below initial UNA" },
        { 3, 3, "partial" }, { 3, 3, "duplicate" }, { 2, 3, "stale" },
        { 16, 16, "cumulative" }, { 24, 24, "complete" }
    };
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_seq_sender_at(&f, start);
    for (unsigned n = 0; n < 3; n++) TEST_REQUIRE(why, tcp_seq_send(&f, n * 8, 8),
        "seq=%08x: send chunk=%u failed", start, n);
    TEST_REQUIRE(why, tcp_seq_wire_bytes(&f, start, 0, 24) && f.conn->sent_seq == start + 24U,
        "seq=%08x: initial stream bytes/sequence/checksum mismatch", start);
    free_output(&f.state);
    for (unsigned i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        fixture_incoming_spec(&f, &spec, 0, NULL, 0);
        spec.ack_seq = start + steps[i].ack;
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_ESTABLISHED &&
            f.conn->acked_seq == start + steps[i].una && f.conn->sent_seq == start + 24U &&
            tcp_seq_buffers(&f, start, steps[i].una, 24),
            "seq=%08x %s ACK: expected UNA=%08x NXT=%08x and retained suffix; actual=%08x/%08x state=%u",
            start, steps[i].name, start + steps[i].una, start + 24U,
            f.conn->acked_seq, f.conn->sent_seq, f.conn->state);
        TEST_REQUIRE(why, f.state.payload_byte_count == 0 && f.state.close_wait.count == 0,
            "seq=%08x %s ACK delivered data/FIN", start, steps[i].name);
        free_output(&f.state);
    }
    fixture_advance_ms(&f, 4000);
    TEST_REQUIRE(why, f.state.out_cnt == 0, "seq=%08x: retransmitted after cumulative ACK", start);
    return RESULT_PASS;
}

static enum result tcp_seq_future_ack(const char **why, uint32_t start, int fin)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[] = { 0, 1 };
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_seq_sender_at(&f, start);
    TEST_REQUIRE(why, tcp_seq_send(&f, 0, 8) && tcp_seq_wire_bytes(&f, start, 0, 8),
        "seq=%08x future ACK setup: missing data", start);
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, 0, data, sizeof(data));
    spec.ack_seq = start + 9U;
    if (fin) spec.tcp_flags |= TEST_TCP_FIN;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->acked_seq == start && f.conn->sent_seq == start + 8U &&
        f.conn->seq_next_expected == 0 && f.conn->state == II_TCP_STATE_ESTABLISHED &&
        f.state.payload_byte_count == 0 && f.state.close_wait.count == 0 && tcp_seq_buffers(&f, start, 0, 8),
        "seq=%08x ACK=NXT+1 FIN=%d: input was not discarded; UNA=%08x RCV.NXT=%u state=%u bytes=%llu FIN callbacks=%u",
        start, fin, f.conn->acked_seq, f.conn->seq_next_expected, f.conn->state,
        (unsigned long long)f.state.payload_byte_count, f.state.close_wait.count);
    TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_ACK, start + 8U, 0),
        "seq=%08x ACK=NXT+1: missing corrective ACK", start);
    free_output(&f.state);
    spec.ack_seq = start + 8U; spec.tcp_flags = TEST_TCP_ACK;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->acked_seq == start + 8U && f.state.payload_byte_count == 2 &&
        f.conn->seq_next_expected == 2 && tcp_seq_buffers(&f, start, 8, 8),
        "seq=%08x: valid ACK/data positive control failed after invalid ACK", start);
    return RESULT_PASS;
}

static enum result tcp_seq_retransmit(const char **why, uint32_t start)
{
    struct fixture f, receiver;
    struct tcp_packet_spec spec;
    if (!fixture_init(&f) || !fixture_init(&receiver)) return RESULT_ERROR;
    tcp_seq_sender_at(&f, start);
    tcp_model_receive_at(&receiver, start);
    TEST_REQUIRE(why, tcp_seq_send(&f, 0, 8) && tcp_seq_wire_bytes(&f, start, 0, 8),
        "seq=%08x retransmission setup: missing data", start);
    for (unsigned round = 0; round < 2; round++) {
        if (round) {
            fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
            TEST_REQUIRE(why, tcp_seq_wire_bytes(&f, start, 3, 8),
                "seq=%08x: RTO did not retransmit intact unacknowledged suffix [3,8)", start);
        }
        /* A separate direct receiver observes the actual transmitted bytes.
         * Rebuild only the peer tuple/ACK/checksum, preserving SEQ and data. */
        for (unsigned i = 0; i < f.state.out_cnt; i++) {
            void *p = f.state.out[i];
            unsigned len = PB_TCP_PAYLOAD_LEN(p);
            if (!len) continue;
            fixture_incoming_spec(&receiver, &spec, ii_ntohl(PB_TCP(p)->seq_be),
                (uint8_t *)PB_TCP(p) + PB_TCP_HDR_LEN(p) * 4, len);
            fixture_deliver(&receiver, build_tcp_packet(&spec, &receiver.state));
        }
        TEST_REQUIRE(why, receiver.state.payload_byte_count == 8 &&
            receiver.conn->seq_next_expected == start + 8U && receiver.state.next_payload == 8,
            "seq=%08x round=%u: receiver delivered duplicate/corrupt stream bytes=%llu RCV.NXT=%08x",
            start, round, (unsigned long long)receiver.state.payload_byte_count, receiver.conn->seq_next_expected);
        free_output(&receiver.state);
        free_output(&f.state);
        fixture_incoming_spec(&f, &spec, 0, NULL, 0);
        spec.ack_seq = start + (round ? 8U : 3U);
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.conn->acked_seq == spec.ack_seq &&
            tcp_seq_buffers(&f, start, round ? 8 : 3, 8),
            "seq=%08x round=%u: partial/final ACK buffer mismatch", start, round);
        free_output(&f.state);
    }
    return RESULT_PASS;
}

static enum result tcp_seq_fin(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_seq_sender_at(&f, start);
    /* FIN starts exactly at each requested boundary, including ffffffff. */
    TEST_REQUIRE(why, test_api_close(f.ws, f.conn, &f.state) == 0, "seq=%08x CLOSE failed", start);
    fixture_run_timers(&f);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_FIN_WAIT1 &&
        f.conn->sent_seq == start + 1U && tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, start, 0),
        "seq=%08x FIN: expected sequence consumption=1, NXT=%08x; actual=%08x", start, start + 1U, f.conn->sent_seq);
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, 0, NULL, 0); spec.ack_seq = start;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_FIN_WAIT1 &&
        test_ring_end(f.ws, &f.conn->sent_ring, 0), "seq=%08x ACK before FIN released FIN", start);
    free_output(&f.state);
    fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
    TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, start, 0) &&
        f.conn->sent_seq == start + 1U, "seq=%08x FIN retransmission consumed extra sequence or disappeared", start);
    free_output(&f.state);
    spec.ack_seq = start + 1U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_FIN_WAIT2 &&
        f.conn->acked_seq == start + 1U && !test_ring_end(f.ws, &f.conn->sent_ring, 0),
        "seq=%08x FIN ACK: expected FIN-WAIT-2 and empty sent queue; state=%u UNA=%08x",
        start, f.conn->state, f.conn->acked_seq);
    return RESULT_PASS;
}

static enum result tcp_seq_overlap(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint8_t data[12];
    static const struct { unsigned offset, len, delivered; } steps[] = {
        {4,4,0}, {2,4,0}, {0,4,8}, {0,8,8}, {6,6,12}
    };
    for (unsigned i = 0; i < sizeof(data); i++) data[i] = i;
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_model_receive_at(&f, start);
    f.state.defer_payload_consumption = 1;
    for (unsigned i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        fixture_incoming_spec(&f, &spec, start + steps[i].offset, data + steps[i].offset, steps[i].len);
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.state.payload_byte_count == steps[i].delivered &&
            f.conn->seq_next_expected == start + steps[i].delivered &&
            f.state.deferred_payload_len == steps[i].delivered,
            "seq=%08x overlap step=%u: expected bytes=%u RCV.NXT=%08x; actual=%llu/%08x deferred=%u",
            start, i, steps[i].delivered, start + steps[i].delivered,
            (unsigned long long)f.state.payload_byte_count, f.conn->seq_next_expected, f.state.deferred_payload_len);
        free_output(&f.state);
    }
    TEST_REQUIRE(why, f.conn->buf.used == 12 && !test_ring_end(f.ws, &f.conn->rx_ring, 0),
        "seq=%08x overlap: expected 12 unconsumed bytes and empty reorder queue; used=%u", start, f.conn->buf.used);
    TEST_REQUIRE(why, test_api_consumed(f.ws, f.conn, 12, &f.state) == 0 &&
        f.conn->buf.used >= f.conn->buf.adv_cnt && f.conn->buf.used - f.conn->buf.adv_cnt == 0,
        "seq=%08x consumed overlap: buffer accounting mismatch used=%u credit=%u", start, f.conn->buf.used, f.conn->buf.adv_cnt);
    free_output(&f.state);
    return RESULT_PASS;
}

static enum result tcp_seq_receive_fin(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[] = {0,1};
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_model_receive_at(&f, start - 2U);
    fixture_incoming_spec(&f, &spec, start - 2U, data, 2);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 2 && f.conn->seq_next_expected == start,
        "seq=%08x receive FIN setup: preceding bytes missing", start);
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, start - 1U, data + 1, 1); spec.tcp_flags |= TEST_TCP_FIN;
    for (unsigned repeat = 0; repeat < 2; repeat++) {
        /* Model actual retransmission after loss, not two inputs in one ACK
         * throttling interval. Virtual time only; no wall-clock sleep. */
        if (repeat) fixture_advance_ms(&f, 1000);
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSE_WAIT && f.state.close_wait.count == 1 &&
            f.state.payload_byte_count == 2 && f.conn->seq_next_expected == start + 1U,
            "seq=%08x overlap FIN repeat=%u: duplicate delivery or FIN sequence/state mismatch", start, repeat);
        TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_ACK, f.conn->sent_seq, start + 1U),
            "seq=%08x overlap FIN repeat=%u: missing ACK=%08x", start, repeat, start + 1U);
        free_output(&f.state);
    }
    return RESULT_PASS;
}

static enum result tcp_seq_window(const char **why, uint32_t start, unsigned input)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[] = {0,1,2,3,4,5,6,7,8,9};
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_model_receive_at(&f, start);
    f.conn->buf.capacity = 8; f.state.defer_payload_consumption = 1;
    /* Separate registry cases keep an edge-response failure from hiding
     * trimming, zero-window and reopening observations. */
    if (input < 2) {
        unsigned len = input;
        fixture_incoming_spec(&f, &spec, start + 8U, data + 8, len);
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.conn->seq_next_expected == start && f.state.payload_byte_count == 0 &&
            tcp_model_has_reply(&f, TEST_TCP_ACK, f.conn->sent_seq, start),
            "seq=%08x right edge len=%u: expected discard and ACK", start, len);
        free_output(&f.state);
        return RESULT_PASS;
    }
    if (input == 2) {
        /* Last in-window byte, then a segment straddling the right edge. */
        fixture_incoming_spec(&f, &spec, start + 7U, data + 7, 1);
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.state.payload_byte_count == 0, "seq=%08x: last window byte delivered before gap", start);
        free_output(&f.state);
    }
    /* The independent zero-window row uses an in-order, exactly fitting
     * segment, so the overlapping trim regression cannot mask it. */
    fixture_incoming_spec(&f, &spec, start, data, input == 2 ? sizeof(data) : 8);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 8 && f.conn->seq_next_expected == start + 8U &&
        f.conn->buf.used == 8 && f.state.deferred_payload_len == 8,
        "seq=%08x window trim: expected bytes=8 used=8 RCV.NXT=%08x; actual=%llu/%u/%08x",
        start, start + 8U, (unsigned long long)f.state.payload_byte_count, f.conn->buf.used, f.conn->seq_next_expected);
    free_output(&f.state);
    /* At zero window, neither data nor FIN may consume sequence space. */
    fixture_incoming_spec(&f, &spec, start + 8U, data + 8, 1); spec.tcp_flags |= TEST_TCP_FIN;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_ESTABLISHED && f.conn->seq_next_expected == start + 8U &&
        f.state.payload_byte_count == 8 && f.state.close_wait.count == 0,
        "seq=%08x zero window: consumed data/FIN", start);
    free_output(&f.state);
    TEST_REQUIRE(why, test_api_consumed(f.ws, f.conn, 8, &f.state) == 0, "consume failed");
    spec.tcp_flags = TEST_TCP_ACK;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 9 && f.conn->seq_next_expected == start + 9U,
        "seq=%08x reopened window: positive-control byte was not delivered", start);
    return RESULT_PASS;
}

static enum result tcp_seq_sack_receive(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[] = {0,1,2,3,4,5,6,7};
    if (!II_CONF_TCP_OPT_SACK_OK) {
        *why = "SACK disabled by II_CONF_TCP_OPT_SACK_OK"; return RESULT_SKIP;
    }
    if (!fixture_init(&f)) return RESULT_ERROR;
    tcp_model_receive_at(&f, start);
    f.conn->flags |= II_TCP_CONN_FLAGS_SACK_OK;
    fixture_incoming_spec(&f, &spec, start + 1U, data + 1, 4);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    int found = 0;
    for (unsigned i = 0; i < f.state.out_cnt; i++) {
        uint8_t *opt = option_find(f.state.out[i], 5);
        if (opt && opt[1] >= 10 && checksum_valid(f.state.out[i]) &&
            ii_ntohl(PB_TCP(f.state.out[i])->ack_seq_be) == start) {
            uint32_t left, right;
            memcpy(&left, opt + 2, 4); memcpy(&right, opt + 6, 4);
            if (ii_ntohl(left) == start + 1U && ii_ntohl(right) == start + 5U) found = 1;
        }
    }
    TEST_REQUIRE(why, found && f.state.payload_byte_count == 0,
        "seq=%08x SACK: missing first block [%08x,%08x) or premature data", start, start + 1U, start + 5U);
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, start, data, 1);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 5 && f.conn->seq_next_expected == start + 5U,
        "seq=%08x SACK gap fill: expected five ordered bytes", start);
    return RESULT_PASS;
}

static enum result tcp_seq_sack_send(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint8_t option[12] = {5,10,0,0,0,0,0,0,0,0,1,1};
    if (!II_CONF_TCP_OPT_SACK_OK) {
        *why = "SACK disabled by II_CONF_TCP_OPT_SACK_OK"; return RESULT_SKIP;
    }
    if (!fixture_init(&f)) return RESULT_ERROR;
    /* Put the SACK block itself across each boundary, not just the hole. */
    uint32_t base = start - 9U;
    tcp_seq_sender_at(&f, base);
    f.conn->flags |= II_TCP_CONN_FLAGS_SACK_OK;
    for (unsigned i = 0; i < 3; i++) TEST_REQUIRE(why, tcp_seq_send(&f, i * 8, 8), "SACK send setup failed");
    TEST_REQUIRE(why, tcp_seq_wire_bytes(&f, base, 0, 24), "seq=%08x SACK setup: incomplete flight", start);
    free_output(&f.state);
    uint32_t left = ii_htonl(base + 8U), right = ii_htonl(base + 24U);
    memcpy(option + 2, &left, 4); memcpy(option + 6, &right, 4);
    fixture_incoming_spec(&f, &spec, 0, NULL, 0); spec.ack_seq = base;
    tcp_packet_add_raw_option(&spec, option, sizeof(option));
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->acked_seq == base && tcp_seq_buffers(&f, base, 0, 24),
        "seq=%08x SACK: selective report advanced cumulative ACK or freed unacknowledged buffers", start);
    uint32_t covered = 0;
    for (unsigned i = 0; i < f.conn->sack.cnt; i++) {
        uint32_t offset = f.conn->sack.extent[i].v - (base + 8U);
        uint32_t len = f.conn->sack.extent[i].l;
        TEST_REQUIRE(why, offset < 16 && len <= 16 - offset,
            "seq=%08x SACK scoreboard contains unreported bytes offset=%u len=%u", start, offset, len);
        for (unsigned n = offset; n < offset + len; n++) covered |= UINT32_C(1) << n;
    }
    TEST_REQUIRE(why, covered == 0xffffU,
        "seq=%08x SACK block was not retained across boundary: coverage=%04x", start, covered);
    free_output(&f.state);
    /* SACK is advisory: after reneging, RTO must still recover the flight.
     * Observe first hole only; do not mandate a particular recovery algorithm. */
    fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
    TEST_REQUIRE(why, tcp_seq_wire_range(&f, base, 0, 8, 24), "seq=%08x SACK: RTO failed to retransmit hole", start);
    free_output(&f.state);
    spec.tcp_options_len = 0; spec.ack_seq = base + 24U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->acked_seq == base + 24U && tcp_seq_buffers(&f, base, 24, 24),
        "seq=%08x SACK: cumulative ACK did not release flight", start);
    return RESULT_PASS;
}

static enum result test_seq_acks_00000000(const char **why)
{ return tcp_seq_acks(why, UINT32_C(0x00000000)); }

static enum result test_seq_future_ack_00000000(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x00000000), 0); }

static enum result test_seq_future_fin_00000000(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x00000000), 1); }

static enum result test_seq_retransmit_00000000(const char **why)
{ return tcp_seq_retransmit(why, UINT32_C(0x00000000)); }

static enum result test_seq_fin_00000000(const char **why)
{ return tcp_seq_fin(why, UINT32_C(0x00000000)); }

static enum result test_seq_overlap_00000000(const char **why)
{ return tcp_seq_overlap(why, UINT32_C(0x00000000)); }

static enum result test_seq_window_00000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000000), 2); }

static enum result test_seq_sack_rx_00000000(const char **why)
{ return tcp_seq_sack_receive(why, UINT32_C(0x00000000)); }

static enum result test_seq_sack_tx_00000000(const char **why)
{ return tcp_seq_sack_send(why, UINT32_C(0x00000000)); }

static enum result test_seq_acks_00000001(const char **why)
{ return tcp_seq_acks(why, UINT32_C(0x00000001)); }

static enum result test_seq_future_ack_00000001(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x00000001), 0); }

static enum result test_seq_future_fin_00000001(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x00000001), 1); }

static enum result test_seq_retransmit_00000001(const char **why)
{ return tcp_seq_retransmit(why, UINT32_C(0x00000001)); }

static enum result test_seq_fin_00000001(const char **why)
{ return tcp_seq_fin(why, UINT32_C(0x00000001)); }

static enum result test_seq_overlap_00000001(const char **why)
{ return tcp_seq_overlap(why, UINT32_C(0x00000001)); }

static enum result test_seq_window_00000001(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000001), 2); }

static enum result test_seq_sack_rx_00000001(const char **why)
{ return tcp_seq_sack_receive(why, UINT32_C(0x00000001)); }

static enum result test_seq_sack_tx_00000001(const char **why)
{ return tcp_seq_sack_send(why, UINT32_C(0x00000001)); }

static enum result test_seq_acks_7fffffff(const char **why)
{ return tcp_seq_acks(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_future_ack_7fffffff(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x7fffffff), 0); }

static enum result test_seq_future_fin_7fffffff(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x7fffffff), 1); }

static enum result test_seq_retransmit_7fffffff(const char **why)
{ return tcp_seq_retransmit(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_fin_7fffffff(const char **why)
{ return tcp_seq_fin(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_overlap_7fffffff(const char **why)
{ return tcp_seq_overlap(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_window_7fffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x7fffffff), 2); }

static enum result test_seq_sack_rx_7fffffff(const char **why)
{ return tcp_seq_sack_receive(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_sack_tx_7fffffff(const char **why)
{ return tcp_seq_sack_send(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_acks_80000000(const char **why)
{ return tcp_seq_acks(why, UINT32_C(0x80000000)); }

static enum result test_seq_future_ack_80000000(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x80000000), 0); }

static enum result test_seq_future_fin_80000000(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0x80000000), 1); }

static enum result test_seq_retransmit_80000000(const char **why)
{ return tcp_seq_retransmit(why, UINT32_C(0x80000000)); }

static enum result test_seq_fin_80000000(const char **why)
{ return tcp_seq_fin(why, UINT32_C(0x80000000)); }

static enum result test_seq_overlap_80000000(const char **why)
{ return tcp_seq_overlap(why, UINT32_C(0x80000000)); }

static enum result test_seq_window_80000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x80000000), 2); }

static enum result test_seq_sack_rx_80000000(const char **why)
{ return tcp_seq_sack_receive(why, UINT32_C(0x80000000)); }

static enum result test_seq_sack_tx_80000000(const char **why)
{ return tcp_seq_sack_send(why, UINT32_C(0x80000000)); }

static enum result test_seq_acks_fffffffe(const char **why)
{ return tcp_seq_acks(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_future_ack_fffffffe(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0xfffffffe), 0); }

static enum result test_seq_future_fin_fffffffe(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0xfffffffe), 1); }

static enum result test_seq_retransmit_fffffffe(const char **why)
{ return tcp_seq_retransmit(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_fin_fffffffe(const char **why)
{ return tcp_seq_fin(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_overlap_fffffffe(const char **why)
{ return tcp_seq_overlap(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_window_fffffffe(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xfffffffe), 2); }

static enum result test_seq_sack_rx_fffffffe(const char **why)
{ return tcp_seq_sack_receive(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_sack_tx_fffffffe(const char **why)
{ return tcp_seq_sack_send(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_acks_ffffffff(const char **why)
{ return tcp_seq_acks(why, UINT32_C(0xffffffff)); }

static enum result test_seq_future_ack_ffffffff(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0xffffffff), 0); }

static enum result test_seq_future_fin_ffffffff(const char **why)
{ return tcp_seq_future_ack(why, UINT32_C(0xffffffff), 1); }

static enum result test_seq_retransmit_ffffffff(const char **why)
{ return tcp_seq_retransmit(why, UINT32_C(0xffffffff)); }

static enum result test_seq_fin_ffffffff(const char **why)
{ return tcp_seq_fin(why, UINT32_C(0xffffffff)); }

static enum result test_seq_overlap_ffffffff(const char **why)
{ return tcp_seq_overlap(why, UINT32_C(0xffffffff)); }

static enum result test_seq_window_ffffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xffffffff), 2); }

static enum result test_seq_sack_rx_ffffffff(const char **why)
{ return tcp_seq_sack_receive(why, UINT32_C(0xffffffff)); }

static enum result test_seq_sack_tx_ffffffff(const char **why)
{ return tcp_seq_sack_send(why, UINT32_C(0xffffffff)); }

static enum result test_seq_right_empty_00000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000000), 0); }

static enum result test_seq_right_data_00000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000000), 1); }

static enum result test_seq_rx_fin_00000000(const char **why)
{ return tcp_seq_receive_fin(why, UINT32_C(0x00000000)); }

static enum result test_seq_right_empty_00000001(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000001), 0); }

static enum result test_seq_right_data_00000001(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000001), 1); }

static enum result test_seq_rx_fin_00000001(const char **why)
{ return tcp_seq_receive_fin(why, UINT32_C(0x00000001)); }

static enum result test_seq_right_empty_7fffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x7fffffff), 0); }

static enum result test_seq_right_data_7fffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x7fffffff), 1); }

static enum result test_seq_rx_fin_7fffffff(const char **why)
{ return tcp_seq_receive_fin(why, UINT32_C(0x7fffffff)); }

static enum result test_seq_right_empty_80000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x80000000), 0); }

static enum result test_seq_right_data_80000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x80000000), 1); }

static enum result test_seq_rx_fin_80000000(const char **why)
{ return tcp_seq_receive_fin(why, UINT32_C(0x80000000)); }

static enum result test_seq_right_empty_fffffffe(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xfffffffe), 0); }

static enum result test_seq_right_data_fffffffe(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xfffffffe), 1); }

static enum result test_seq_rx_fin_fffffffe(const char **why)
{ return tcp_seq_receive_fin(why, UINT32_C(0xfffffffe)); }

static enum result test_seq_right_empty_ffffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xffffffff), 0); }

static enum result test_seq_right_data_ffffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xffffffff), 1); }

static enum result test_seq_rx_fin_ffffffff(const char **why)
{ return tcp_seq_receive_fin(why, UINT32_C(0xffffffff)); }

static enum result test_seq_zero_window_00000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000000), 3); }

static enum result test_seq_zero_window_00000001(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x00000001), 3); }

static enum result test_seq_zero_window_7fffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x7fffffff), 3); }

static enum result test_seq_zero_window_80000000(const char **why)
{ return tcp_seq_window(why, UINT32_C(0x80000000), 3); }

static enum result test_seq_zero_window_fffffffe(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xfffffffe), 3); }

static enum result test_seq_zero_window_ffffffff(const char **why)
{ return tcp_seq_window(why, UINT32_C(0xffffffff), 3); }

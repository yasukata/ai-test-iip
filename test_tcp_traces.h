/* Actual OPEN/CLOSE operations and wire inputs complement the placed-state
 * model. The unrelated base-fixture connection only supplies local addresses. */
static enum result tcp_trace_open(const char **why, struct fixture *f, int passive,
        uint32_t *iss)
{
    struct tcp_packet_spec spec;
    const uint16_t peer_port = ii_htons(21000);
    if (!fixture_init(f)) return RESULT_ERROR;
    if (passive) {
        TEST_REQUIRE(why, test_tcp_listen(&f->state, ii_htonl(f->conn->src_ip[0]),
            ii_htons(f->conn->src_port), 0, 0, NULL), "listener setup failed");
        fixture_incoming_spec(f, &spec, 10000, NULL, 0);
        spec.src_port_be = peer_port;
        spec.tcp_flags = TEST_TCP_SYN;
        fixture_deliver(f, build_tcp_packet(&spec, &f->state));
    } else {
        TEST_REQUIRE(why, test_api_connect(f->ws, f->local_mac,
            ii_htonl(f->conn->src_ip[0]), ii_htons(15000), f->peer_mac,
            ii_htonl(f->conn->dst_ip[0]), peer_port, &f->state) == 0,
            "active OPEN failed");
        fixture_run_timers(f);
    }
    struct ii_tcp_conn *conn = fixture_find_peer_port(f, peer_port);
    TEST_REQUIRE(why, conn && conn->state ==
        (passive ? II_TCP_STATE_SYN_RECVD : II_TCP_STATE_SYN_SENT),
        "%s OPEN: expected handshake state; actual=%u", passive ? "passive" : "active",
        conn ? conn->state : 255);
    f->conn = conn;
    void *syn = output_nth_ethertype(&f->state, 0x0800, 0);
    TEST_REQUIRE(why, syn && PB_TCP_HDR_HAS_SYN(syn), "OPEN emitted no SYN");
    *iss = ii_ntohl(PB_TCP(syn)->seq_be);
    TEST_REQUIRE(why, tcp_model_has_reply(f, TEST_TCP_SYN | (passive ? TEST_TCP_ACK : 0),
        *iss, passive ? 10001 : 0), "OPEN emitted invalid SYN sequence/ACK/checksum");
    free_output(&f->state);
    test_event_log_clear(&f->state);
    return RESULT_PASS;
}

static enum result tcp_trace_establish(const char **why, struct fixture *f, int passive,
        uint32_t iss)
{
    struct tcp_packet_spec spec;
    fixture_incoming_spec(f, &spec, passive ? 10001 : 10000, NULL, 0);
    spec.tcp_flags = TEST_TCP_ACK | (passive ? 0 : TEST_TCP_SYN);
    spec.ack_seq = iss + 1U;
    fixture_deliver(f, build_tcp_packet(&spec, &f->state));
    TEST_REQUIRE(why, f->conn->state == II_TCP_STATE_ESTABLISHED &&
        f->conn->seq_next_expected == 10001 && f->conn->acked_seq == iss + 1U,
        "handshake: expected ESTABLISHED RCV.NXT=10001 UNA=%u; actual=%u/%u/%u",
        iss + 1U, f->conn->state, f->conn->seq_next_expected, f->conn->acked_seq);
    TEST_REQUIRE(why, test_event_count(&f->state, TEST_EVENT_CALLBACK,
        passive ? TEST_CALLBACK_ACCEPTED : TEST_CALLBACK_CONNECTED) == 1,
        "handshake: expected one application connection notification");
    if (!passive) TEST_REQUIRE(why, tcp_model_has_reply(f, TEST_TCP_ACK, iss + 1U, 10001),
        "active handshake: missing final ACK");
    free_output(&f->state);
    return RESULT_PASS;
}

/* No TCB exists for the tested tuple. LISTEN is the documented callback-side
 * binding, not a fabricated iip state. Repeat each input to check duplicates. */
static enum result tcp_model_unconnected(const char **why, int listen, unsigned input)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    static const uint16_t flags[] = { TEST_TCP_SYN, TEST_TCP_ACK, TEST_TCP_FIN,
        TEST_TCP_RST, 0, TEST_TCP_SYN | TEST_TCP_ACK,
        TEST_TCP_RST | TEST_TCP_SYN | TEST_TCP_FIN | TEST_TCP_ACK };
    const uint8_t data[] = { 0, 1 };
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.state.listener_mode = 1; /* no bindings means CLOSED */
    if (listen) TEST_REQUIRE(why, test_tcp_listen(&f.state,
        ii_htonl(f.conn->src_ip[0]), ii_htons(15000), 0, 0, NULL), "LISTEN setup failed");
    fixture_incoming_spec(&f, &spec, UINT32_MAX, input == 4 ? data : NULL, input == 4 ? 2 : 0);
    spec.src_port_be = ii_htons(21000); spec.dst_port_be = ii_htons(15000);
    spec.tcp_flags = flags[input]; spec.ack_seq = 777;
    for (unsigned repeat = 0; repeat < 2; repeat++) {
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.state.payload_byte_count == 0 && f.state.close_wait.count == 0,
            "%s flags=%x repeat=%u: unexpected application data/FIN", listen ? "LISTEN" : "CLOSED", flags[input], repeat);
        if (listen && input == 0) {
            struct ii_tcp_conn *c = fixture_find_peer_port(&f, spec.src_port_be);
            TEST_REQUIRE(why, c && c->state == II_TCP_STATE_SYN_RECVD,
                "LISTEN SYN repeat=%u: no SYN-RECEIVED child", repeat);
            /* Duplicate SYN may use the existing retransmission timer. */
            if (!repeat) TEST_REQUIRE(why, tcp_model_has_reply(&f,
                TEST_TCP_SYN | TEST_TCP_ACK, c->iss, 0), "LISTEN SYN: bad SYN+ACK");
        } else {
            int silent = (flags[input] & TEST_TCP_RST) ||
                (listen && !(flags[input] & TEST_TCP_ACK));
            if (silent) TEST_REQUIRE(why, f.state.out_cnt == 0,
                "%s flags=%x: expected discard, packets=%u", listen ? "LISTEN" : "CLOSED", flags[input], f.state.out_cnt);
            else {
                uint32_t end = spec.seq + spec.payload_len + !!(flags[input] & TEST_TCP_SYN) + !!(flags[input] & TEST_TCP_FIN);
                uint16_t reply = TEST_TCP_RST | ((flags[input] & TEST_TCP_ACK) ? 0 : TEST_TCP_ACK);
                TEST_REQUIRE(why, tcp_model_has_reply(&f, reply,
                    (flags[input] & TEST_TCP_ACK) ? spec.ack_seq : 0, end),
                    "%s flags=%x: expected RST flags=%x seq=%u ack=%u; packets=%u",
                    listen ? "LISTEN" : "CLOSED", flags[input], reply,
                    (flags[input] & TEST_TCP_ACK) ? spec.ack_seq : 0, end, f.state.out_cnt);
            }
            TEST_REQUIRE(why, fixture_find_peer_port(&f, spec.src_port_be) == NULL,
                "%s flags=%x: unexpected child connection", listen ? "LISTEN" : "CLOSED", flags[input]);
        }
        free_output(&f.state);
    }
    return RESULT_PASS;
}

/* Handshake ACK limits, flags and sequence acceptance. Each negative input is
 * followed by the valid handshake, so silence alone cannot pass a dead fixture. */
static enum result tcp_model_handshake(const char **why, int passive, unsigned input)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint32_t iss;
    enum result r = tcp_trace_open(why, &f, passive, &iss);
    if (r != RESULT_PASS) return r;
    uint8_t initial = f.conn->state;
    uint32_t receive = f.conn->seq_next_expected;
    const uint8_t data[] = { 0, 1 };
    fixture_incoming_spec(&f, &spec, passive ? 10001 : 10000, NULL, 0);
    spec.ack_seq = iss + 1U;
    switch (input) {
    case 0: spec.ack_seq = iss; break;
    case 1: spec.ack_seq = iss + 2U; break;
    case 2: spec.tcp_flags = TEST_TCP_FIN; break;
    case 3: spec.tcp_flags = 0; spec.payload = data; spec.payload_len = sizeof(data); break;
    case 4: spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
        if (passive) spec.seq += 0x100000U; else spec.ack_seq = iss + 2U;
        break;
    case 5: spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK | TEST_TCP_SYN;
        /* RST precedence; passive SYN must not reset receive sequencing first. */
        break;
    case 6: spec.tcp_flags = TEST_TCP_ACK; spec.payload = data; spec.payload_len = sizeof(data);
        if (passive) spec.seq += 0x100000U;
        break;
    case 7: spec.tcp_flags = TEST_TCP_FIN | TEST_TCP_ACK; break;
    default: *why = "unknown handshake input"; return RESULT_ERROR;
    }
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    if (input == 5) {
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSED && f.state.out_cnt == 0 &&
            f.state.payload_byte_count == 0,
            "%s RST: expected closed/discarded child; actual state=%u packets=%u",
            passive ? "SYN-RECEIVED" : "SYN-SENT", f.conn->state, f.state.out_cnt);
        /* RFC 9293 says the passive user need not be informed, not that
         * notification is forbidden. Active refusal must notify the user. */
        unsigned closed = test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED);
        TEST_REQUIRE(why, passive ? closed <= 1U : closed == 1U,
            "handshake RST: incorrect active/passive notification");
        if (passive) {
            /* Listener survives removal of its half-open child. */
            fixture_incoming_spec(&f, &spec, 10000, NULL, 0);
            spec.tcp_flags = TEST_TCP_SYN;
            fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
            struct ii_tcp_conn *c = fixture_find_peer_port(&f, spec.src_port_be);
            TEST_REQUIRE(why, c && c->state == II_TCP_STATE_SYN_RECVD,
                "passive reset removed listener or prevented a new SYN");
        }
        return RESULT_PASS;
    }
    if (passive && input == 7) {
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSE_WAIT &&
            f.conn->seq_next_expected == 10002 && f.state.close_wait.count == 1 &&
            test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_ACCEPTED) == 1,
            "SYN-RECEIVED FIN+ACK: expected CLOSE-WAIT RCV.NXT=10002; actual=%u/%u",
            f.conn->state, f.conn->seq_next_expected);
        TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 1U, 10002),
            "SYN-RECEIVED FIN+ACK: missing FIN acknowledgment");
        return RESULT_PASS;
    }
    TEST_REQUIRE(why, f.conn->state == initial && f.conn->seq_next_expected == receive &&
        f.conn->acked_seq == iss && f.state.payload_byte_count == 0 && f.state.close_wait.count == 0,
        "%s input=%u: discard changed state/RCV.NXT/UNA or delivered data: %u/%u/%u/%llu",
        passive ? "SYN-RECEIVED" : "SYN-SENT", input, f.conn->state,
        f.conn->seq_next_expected, f.conn->acked_seq, (unsigned long long)f.state.payload_byte_count);
    if (input < 2) {
        /* The optional RFC5961 ACK validation in 3.10.7.4 can reject a
         * future ACK with a challenge ACK before the SYN-RECEIVED rule. */
        int challenge = passive && input == 1 &&
            tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 1U, 10001);
        TEST_REQUIRE(why, challenge || tcp_model_has_reply(&f, TEST_TCP_RST, spec.ack_seq, 0),
            "handshake invalid ACK=%u: required reset/challenge response missing", spec.ack_seq);
    }
    else if (passive && input == 6) TEST_REQUIRE(why,
        tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 1U, 10001), "SYN-RECEIVED outside-window data: missing ACK");
    else TEST_REQUIRE(why, f.state.out_cnt == 0, "handshake discarded input=%u emitted %u packets", input, f.state.out_cnt);
    free_output(&f.state);
    return tcp_trace_establish(why, &f, passive, iss);
}

static enum result test_trace_active_loss(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint32_t iss;
    enum result r = tcp_trace_open(why, &f, 0, &iss);
    if (r != RESULT_PASS) return r;
    fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_SYN_SENT &&
        tcp_model_has_reply(&f, TEST_TCP_SYN, iss, 0), "lost SYN: missing retransmission with original ISS");
    free_output(&f.state);
    r = tcp_trace_establish(why, &f, 0, iss);
    if (r != RESULT_PASS) return r;
    /* Drop final ACK: retransmitted peer SYN+ACK must elicit another ACK. */
    fixture_incoming_spec(&f, &spec, 10000, NULL, 0);
    spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK; spec.ack_seq = iss + 1U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_ESTABLISHED &&
        f.conn->seq_next_expected == 10001 && tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 1U, 10001) &&
        test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CONNECTED) == 1,
        "lost handshake ACK: duplicate SYN+ACK changed state, repeated callback or was not ACKed");
    free_output(&f.state);
    TEST_REQUIRE(why, test_api_close(f.ws, f.conn, &f.state) == 0, "active CLOSE failed");
    fixture_run_timers(&f);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_FIN_WAIT1 &&
        tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, iss + 1U, 10001), "active CLOSE: no FIN-WAIT-1/FIN");
    free_output(&f.state);
    fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_FIN_WAIT1 &&
        tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, iss + 1U, 10001), "lost FIN: missing retransmission");
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, 10001, NULL, 0); spec.ack_seq = iss + 2U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_FIN_WAIT2 &&
        !test_ring_end(f.ws, &f.conn->sent_ring, 0), "FIN ACK: no FIN-WAIT-2 or FIN buffer still queued");
    free_output(&f.state);
    spec.tcp_flags |= TEST_TCP_FIN;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_TIME_WAIT &&
        f.conn->seq_next_expected == 10002 && tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 2U, 10002),
        "peer FIN: no TIME-WAIT/ACK");
    free_output(&f.state);
    fixture_advance_ms(&f, 1000);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_TIME_WAIT &&
        f.conn->seq_next_expected == 10002 && tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 2U, 10002),
        "lost FIN ACK: retransmitted FIN consumed twice or not ACKed");
    free_output(&f.state);
    return RESULT_PASS;
}

static enum result test_trace_passive_loss(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint32_t iss;
    enum result r = tcp_trace_open(why, &f, 1, &iss);
    if (r != RESULT_PASS) return r;
    fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_SYN_RECVD &&
        tcp_model_has_reply(&f, TEST_TCP_SYN | TEST_TCP_ACK, iss, 10001), "lost SYN+ACK: missing retransmission");
    free_output(&f.state);
    r = tcp_trace_establish(why, &f, 1, iss);
    if (r != RESULT_PASS) return r;
    fixture_incoming_spec(&f, &spec, 10001, NULL, 0);
    spec.tcp_flags |= TEST_TCP_FIN; spec.ack_seq = iss + 1U;
    for (unsigned repeat = 0; repeat < 2; repeat++) {
        fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
        TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSE_WAIT && f.state.close_wait.count == 1 &&
            f.conn->seq_next_expected == 10002 && tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 1U, 10002),
            "passive FIN repeat=%u: wrong CLOSE-WAIT, callback count or ACK", repeat);
        free_output(&f.state);
    }
    TEST_REQUIRE(why, test_api_close(f.ws, f.conn, &f.state) == 0, "passive CLOSE failed");
    fixture_run_timers(&f);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_LAST_ACK &&
        tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, iss + 1U, 10002), "passive CLOSE: missing LAST-ACK/FIN");
    free_output(&f.state);
    fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 501);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_LAST_ACK &&
        tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, iss + 1U, 10002), "LAST-ACK lost FIN: missing retransmission");
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, 10002, NULL, 0); spec.ack_seq = iss + 2U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSED &&
        test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 1 &&
        !test_ring_end(f.ws, &f.conn->sent_ring, 0), "LAST-ACK completion: state/callback/queue mismatch");
    return RESULT_PASS;
}

static enum result test_trace_simultaneous_open(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint32_t iss;
    enum result r = tcp_trace_open(why, &f, 0, &iss);
    if (r != RESULT_PASS) return r;
    fixture_incoming_spec(&f, &spec, 10000, NULL, 0); spec.tcp_flags = TEST_TCP_SYN;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_SYN_RECVD &&
        tcp_model_has_reply(&f, TEST_TCP_SYN | TEST_TCP_ACK, iss, 10001),
        "crossing SYN: missing SYN-RECEIVED/SYN+ACK with original ISS");
    free_output(&f.state);
    r = tcp_trace_establish(why, &f, 0, iss);
    if (r != RESULT_PASS) return r;
    TEST_REQUIRE(why, test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_ACCEPTED) == 0,
        "simultaneous active OPEN incorrectly notified passive acceptance");
    return RESULT_PASS;
}

static enum result test_trace_simultaneous_close(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint32_t iss;
    enum result r = tcp_trace_open(why, &f, 0, &iss);
    if (r != RESULT_PASS) return r;
    r = tcp_trace_establish(why, &f, 0, iss);
    if (r != RESULT_PASS) return r;
    TEST_REQUIRE(why, test_api_close(f.ws, f.conn, &f.state) == 0, "simultaneous CLOSE failed");
    fixture_run_timers(&f);
    TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, iss + 1U, 10001),
        "simultaneous CLOSE: missing local FIN");
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, 10001, NULL, 0);
    spec.tcp_flags |= TEST_TCP_FIN; spec.ack_seq = iss + 1U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSING &&
        tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 2U, 10002),
        "crossing FIN+ACK: expected CLOSING and ACK, actual state=%u packets=%u", f.conn->state, f.state.out_cnt);
    free_output(&f.state);
    spec.seq++; spec.tcp_flags = TEST_TCP_ACK; spec.ack_seq++;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_TIME_WAIT, "CLOSING FIN ACK: no TIME-WAIT");
    return RESULT_PASS;
}

static enum result test_trace_timewait_restart(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    uint32_t iss;
    const uint64_t msl_ms = (uint64_t)IIP_CONF_TCP_MSL_SEC * 1000U;
    enum result r = tcp_trace_open(why, &f, 0, &iss);
    if (r != RESULT_PASS) return r;
    r = tcp_trace_establish(why, &f, 0, iss);
    if (r != RESULT_PASS) return r;
    TEST_REQUIRE(why, test_api_close(f.ws, f.conn, &f.state) == 0, "TIME-WAIT setup: CLOSE failed");
    fixture_run_timers(&f);
    TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK, iss + 1U, 10001),
        "TIME-WAIT setup: missing local FIN");
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, 10001, NULL, 0);
    spec.tcp_flags |= TEST_TCP_FIN; spec.ack_seq = iss + 2U;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_TIME_WAIT, "TIME-WAIT setup: combined FIN+ACK did not close");
    free_output(&f.state);
    fixture_advance_ms(&f, msl_ms);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_TIME_WAIT &&
        tcp_model_has_reply(&f, TEST_TCP_ACK, iss + 2U, 10002), "retransmitted TIME-WAIT FIN was not acknowledged");
    free_output(&f.state);
    /* Old deadline has passed; new deadline still lies almost one MSL away.
     * One 500-ms timer tick permits expiry at the old deadline to be observed. */
    fixture_advance_ms(&f, msl_ms + 500);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_TIME_WAIT &&
        test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 0,
        "duplicate FIN did not restart 2MSL: expected TIME-WAIT; state=%u", f.conn->state);
    fixture_advance_ms(&f, msl_ms + 500);
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSED &&
        test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 1,
        "restarted TIME-WAIT did not eventually close once");
    return RESULT_PASS;
}

static enum result test_unconnected_0_0(const char **why)
{ return tcp_model_unconnected(why, 0, 0); }

static enum result test_unconnected_0_1(const char **why)
{ return tcp_model_unconnected(why, 0, 1); }

static enum result test_unconnected_0_2(const char **why)
{ return tcp_model_unconnected(why, 0, 2); }

static enum result test_unconnected_0_3(const char **why)
{ return tcp_model_unconnected(why, 0, 3); }

static enum result test_unconnected_0_4(const char **why)
{ return tcp_model_unconnected(why, 0, 4); }

static enum result test_unconnected_0_5(const char **why)
{ return tcp_model_unconnected(why, 0, 5); }

static enum result test_unconnected_0_6(const char **why)
{ return tcp_model_unconnected(why, 0, 6); }

static enum result test_unconnected_1_0(const char **why)
{ return tcp_model_unconnected(why, 1, 0); }

static enum result test_unconnected_1_1(const char **why)
{ return tcp_model_unconnected(why, 1, 1); }

static enum result test_unconnected_1_2(const char **why)
{ return tcp_model_unconnected(why, 1, 2); }

static enum result test_unconnected_1_3(const char **why)
{ return tcp_model_unconnected(why, 1, 3); }

static enum result test_unconnected_1_4(const char **why)
{ return tcp_model_unconnected(why, 1, 4); }

static enum result test_unconnected_1_5(const char **why)
{ return tcp_model_unconnected(why, 1, 5); }

static enum result test_unconnected_1_6(const char **why)
{ return tcp_model_unconnected(why, 1, 6); }

static enum result test_handshake_0_0(const char **why)
{ return tcp_model_handshake(why, 0, 0); }

static enum result test_handshake_0_1(const char **why)
{ return tcp_model_handshake(why, 0, 1); }

static enum result test_handshake_0_2(const char **why)
{ return tcp_model_handshake(why, 0, 2); }

static enum result test_handshake_0_3(const char **why)
{ return tcp_model_handshake(why, 0, 3); }

static enum result test_handshake_0_4(const char **why)
{ return tcp_model_handshake(why, 0, 4); }

static enum result test_handshake_0_5(const char **why)
{ return tcp_model_handshake(why, 0, 5); }

static enum result test_handshake_0_6(const char **why)
{ return tcp_model_handshake(why, 0, 6); }

static enum result test_handshake_0_7(const char **why)
{ return tcp_model_handshake(why, 0, 7); }

static enum result test_handshake_1_0(const char **why)
{ return tcp_model_handshake(why, 1, 0); }

static enum result test_handshake_1_1(const char **why)
{ return tcp_model_handshake(why, 1, 1); }

static enum result test_handshake_1_2(const char **why)
{ return tcp_model_handshake(why, 1, 2); }

static enum result test_handshake_1_3(const char **why)
{ return tcp_model_handshake(why, 1, 3); }

static enum result test_handshake_1_4(const char **why)
{ return tcp_model_handshake(why, 1, 4); }

static enum result test_handshake_1_5(const char **why)
{ return tcp_model_handshake(why, 1, 5); }

static enum result test_handshake_1_6(const char **why)
{ return tcp_model_handshake(why, 1, 6); }

static enum result test_handshake_1_7(const char **why)
{ return tcp_model_handshake(why, 1, 7); }

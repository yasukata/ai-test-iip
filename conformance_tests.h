/* Additional independent observations; algorithm-specific assertions are named profiles. */
static enum result test_abort_notification(const char **why)
{
    struct fixture normal, aborted;
    struct tcp_packet_spec spec;
    if (!fixture_init(&normal) || !fixture_init(&aborted)) return RESULT_ERROR;
    fixture_incoming_spec(&normal, &spec, 0, NULL, 0);
    spec.tcp_flags |= TEST_TCP_FIN;
    fixture_deliver(&normal, build_tcp_packet(&spec, &normal.state));
    if (normal.state.close_wait.count != 1) {
        *why = "normal peer FIN was not reported through CLOSE_WAIT"; return RESULT_FAIL;
    }
    free_output(&normal.state);
    if (test_api_close(normal.ws, normal.conn, &normal.state) == UINT16_MAX) return RESULT_ERROR;
    fixture_run_timers(&normal);
    free_output(&normal.state);
    fixture_incoming_spec(&normal, &spec, 1, NULL, 0);
    spec.ack_seq = normal.conn->seq;
    fixture_deliver(&normal, build_tcp_packet(&spec, &normal.state));
    fixture_run_timers(&normal);
    fixture_incoming_spec(&aborted, &spec, 0, NULL, 0);
    spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
    fixture_deliver(&aborted, build_tcp_packet(&spec, &aborted.state));
    /* Application-visible callback histories, not the injected flags, are the oracle. */
    if (test_event_count(&normal.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) != 1 ||
            test_event_count(&aborted.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) != 1 ||
            aborted.state.close_wait.count != 0) {
        *why = "FIN completion and RST abort did not have distinguishable callback histories";
        return RESULT_FAIL;
    }
    return RESULT_PASS;
}

static enum result test_sender_sws_profile(const char **why)
{
    struct fixture f;
    if (!fixture_init(&f)) return RESULT_ERROR;
    uint16_t mss = f.conn->mss;
    if (mss > f.conn->path_mtu - 40U) mss = f.conn->path_mtu - 40U;
    return test_sws_override_timeout(why, mss) && test_sws_push_followed_by_fin(why, mss)
        ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_tfo_no_option(const char **why)
{
    return test_fastopen_rejected_syn_data_case(FASTOPEN_REJECT_NO_OPTION, why) ? RESULT_PASS : RESULT_FAIL;
}
static enum result test_tfo_cookie_request(const char **why)
{
    return test_fastopen_rejected_syn_data_case(FASTOPEN_REJECT_REQUEST, why) ? RESULT_PASS : RESULT_FAIL;
}
static enum result test_tfo_invalid_cookie(const char **why)
{
    return test_fastopen_rejected_syn_data_case(FASTOPEN_REJECT_INVALID_COOKIE, why) ? RESULT_PASS : RESULT_FAIL;
}


/* RFC 9293 MUST-51: a source route specified at active OPEN must be taken.
 * The route reaches iip through IIP_OPS_IPV4_OPT_SEND (test_backend.h).
 * SYN, handshake ACK and a data segment must each carry the option, be
 * addressed to the first hop, have a frame length equal to the IPv4 total
 * length, and keep valid IPv4/TCP checksums (pseudo-header uses the
 * ultimate destination). */
static int must51_all_routed(struct fixture *f, uint32_t wire_dst_be,
        uint32_t final_dst_be, const uint8_t *option, uint16_t option_len)
{
    unsigned int i;
    if (!f->state.out_cnt) return 0;
    for (i = 0; i < f->state.out_cnt; i++) {
        void *pkt = f->state.out[i];
        if (iip_ops_pkt_get_len(pkt, &f->state) !=
                (uint16_t)(iip_ops_l2_hdr_len(pkt, &f->state) + PB_IP4_TOTAL_LEN(pkt)))
            return 0;
        if (!test_packet_has_source_route(pkt, wire_dst_be,
                final_dst_be, option, option_len))
            return 0;
    }
    return 1;
}

static enum result test_source_route_active_open(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    struct ii_tcp_conn *conn;
    uint8_t option[40];
    uint16_t option_len;
    const uint16_t local_port_be = ii_htons(14010);
    const uint16_t peer_port_be = ii_htons(25010);
    const uint32_t wire_dst_be = ii_htonl(0xcb007101U); /* first hop */
    uint32_t final_dst_be, address_be[1];
    if (!fixture_init(&f)) return RESULT_ERROR;
    final_dst_be = ii_htonl(f.conn->dst_ip[0]);
    address_be[0] = final_dst_be;
    option_len = test_make_source_route_option(option, 131 /* LSRR */, 4,
            address_be, 1);
    if (!test_source_route_add(&f.state, 1, ii_htonl(f.conn->src_ip[0]),
            local_port_be, final_dst_be, peer_port_be, wire_dst_be,
            option, option_len)) return RESULT_ERROR;
    if (test_tcp_active_open(f.ws, f.local_mac,
            &(uint32_t){ ii_htonl(f.conn->src_ip[0]) }, local_port_be,
            f.peer_mac, final_dst_be, peer_port_be, &f.state) == 0xffff)
        return RESULT_ERROR;
    fixture_run_timers(&f);
    conn = fixture_find_peer_port(&f, peer_port_be);
    if (!conn || f.state.out_cnt != 1 || !PB_TCP_HDR_HAS_SYN(f.state.out[0])) {
        *why = "active OPEN did not emit exactly one SYN"; return RESULT_ERROR;
    }
    if (!must51_all_routed(&f, wire_dst_be, final_dst_be, option, option_len)) {
        *why = "SYN did not take the application source route"; return RESULT_FAIL;
    }
    free_output(&f.state);
    /* SYN-ACK without IP options: the application route must still apply. */
    fixture_incoming_spec(&f, &spec, 100, NULL, 0);
    spec.src_port_be = peer_port_be;
    spec.dst_port_be = local_port_be;
    spec.ack_seq = conn->seq;
    spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    if (conn->state != II_TCP_STATE_ESTABLISHED) {
        *why = "handshake precondition failed"; return RESULT_ERROR;
    }
    if (f.state.out_cnt &&
            !must51_all_routed(&f, wire_dst_be, final_dst_be, option, option_len)) {
        *why = "handshake ACK did not take the application source route"; return RESULT_FAIL;
    }
    free_output(&f.state);
    {
        void *payload = iip_ops_pkt_alloc(&f.state);
        if (!payload) return RESULT_ERROR;
        memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, 100);
        iip_ops_pkt_set_len(payload, 100, &f.state);
        test_api_send(f.ws, conn, payload, 0, &f.state);
        fixture_run_timers(&f);
    }
    if (!f.state.out_cnt) {
        *why = "data segment not emitted"; return RESULT_INCONCLUSIVE;
    }
    if (!must51_all_routed(&f, wire_dst_be, final_dst_be, option, option_len)) {
        *why = "data segment did not take the application source route"; return RESULT_FAIL;
    }
    return RESULT_PASS;
}

/* RFC 9293 MUST-52: an application-specified source route takes precedence
 * over a source route received in a datagram.  The SYN-ACK carries a
 * different LSRR; the handshake ACK and later data must still use the
 * application route.  A control connection without an application route
 * shows that the received route is otherwise adopted, so the precedence
 * verdict is not a vacuous "no route captured" pass. */
static int must52_deliver_routed_synack(struct fixture *f, struct ii_tcp_conn *conn,
        uint16_t local_port_be, uint16_t peer_port_be, uint32_t hop_be)
{
    struct tcp_packet_spec spec;
    uint8_t option[40];
    uint16_t option_len;
    uint32_t address_be[1] = { hop_be };
    fixture_incoming_spec(f, &spec, 100, NULL, 0);
    spec.src_port_be = peer_port_be;
    spec.dst_port_be = local_port_be;
    spec.ack_seq = conn->seq;
    spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
    /* Route fully traversed (pointer past the end), as on arrival. */
    option_len = test_make_source_route_option(option, 131, 8, address_be, 1);
    memcpy(spec.ip_options, option, option_len);
    spec.ip_options_len = option_len;
    fixture_deliver(f, build_tcp_packet(&spec, &f->state));
    return conn->state == II_TCP_STATE_ESTABLISHED;
}

static enum result test_source_route_precedence(const char **why)
{
    struct fixture f, control;
    struct ii_tcp_conn *conn;
    uint8_t app_option[40];
    uint16_t app_option_len;
    const uint16_t local_port_be = ii_htons(14011);
    const uint16_t peer_port_be = ii_htons(25011);
    const uint32_t app_hop_be = ii_htonl(0xcb007101U);
    const uint32_t received_hop_be = ii_htonl(0xcb007102U);
    uint32_t final_dst_be, local_be, address_be[1];
    unsigned int i;

    /* Control: no application route; the received route must be adopted. */
    if (!fixture_init(&control)) return RESULT_ERROR;
    local_be = ii_htonl(control.conn->src_ip[0]);
    final_dst_be = ii_htonl(control.conn->dst_ip[0]);
    if (test_tcp_active_open(control.ws, control.local_mac, &local_be,
            local_port_be, control.peer_mac, final_dst_be, peer_port_be,
            &control.state) == 0xffff) return RESULT_ERROR;
    fixture_run_timers(&control);
    conn = fixture_find_peer_port(&control, peer_port_be);
    if (!conn) return RESULT_ERROR;
    free_output(&control.state);
    if (!must52_deliver_routed_synack(&control, conn, local_port_be,
            peer_port_be, received_hop_be)) {
        *why = "control handshake failed"; return RESULT_ERROR;
    }
    if (!control.state.out_cnt ||
            PB_IP4(control.state.out[0])->dst_be != received_hop_be ||
            !test_ip4_source_route_option(control.state.out[0], &(uint16_t){ 0 })) {
        *why = "precondition: received route is not adopted without an application route; precedence not observable";
        return RESULT_INCONCLUSIVE;
    }

    /* Test: application route specified at active OPEN. */
    if (!fixture_init(&f)) return RESULT_ERROR;
    address_be[0] = final_dst_be;
    app_option_len = test_make_source_route_option(app_option, 131, 4,
            address_be, 1);
    if (!test_source_route_add(&f.state, 1, local_be, local_port_be,
            final_dst_be, peer_port_be, app_hop_be, app_option,
            app_option_len)) return RESULT_ERROR;
    if (test_tcp_active_open(f.ws, f.local_mac, &local_be, local_port_be,
            f.peer_mac, final_dst_be, peer_port_be, &f.state) == 0xffff)
        return RESULT_ERROR;
    fixture_run_timers(&f);
    conn = fixture_find_peer_port(&f, peer_port_be);
    if (!conn || !must51_all_routed(&f, app_hop_be, final_dst_be,
            app_option, app_option_len)) {
        *why = "precondition: SYN did not take the application route (see MUST-51)";
        return RESULT_INCONCLUSIVE;
    }
    free_output(&f.state);
    if (!must52_deliver_routed_synack(&f, conn, local_port_be, peer_port_be,
            received_hop_be)) {
        *why = "handshake precondition failed"; return RESULT_ERROR;
    }
    if (f.state.out_cnt && !must51_all_routed(&f, app_hop_be, final_dst_be,
            app_option, app_option_len)) {
        *why = "a received source route overrode the application route on the handshake ACK";
        return RESULT_FAIL;
    }
    free_output(&f.state);
    {
        void *payload = iip_ops_pkt_alloc(&f.state);
        if (!payload) return RESULT_ERROR;
        memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, 100);
        iip_ops_pkt_set_len(payload, 100, &f.state);
        test_api_send(f.ws, conn, payload, 0, &f.state);
        fixture_run_timers(&f);
    }
    if (!f.state.out_cnt) {
        *why = "data segment not emitted"; return RESULT_INCONCLUSIVE;
    }
    if (!must51_all_routed(&f, app_hop_be, final_dst_be, app_option, app_option_len)) {
        *why = "a received source route overrode the application route on data";
        return RESULT_FAIL;
    }
    for (i = 0; i < f.state.out_cnt; i++)
        if (PB_IP4(f.state.out[i])->dst_be == received_hop_be) {
            *why = "segment addressed to the received route's hop"; return RESULT_FAIL;
        }
    return RESULT_PASS;
}

/*
 * Nagle must hold only new small data, never control segments queued
 * behind it.  Each case first establishes "one octet outstanding, a second
 * octet held by Nagle"; if the stack does not hold it, the scenario is not
 * reachable and the case is NOT_APPLICABLE (SHLD-7 reports that).  The
 * RTO is made long (via SRTT/RTTVAR) so that a retransmission, which also
 * carries an ACK, cannot mask a held control segment; a retransmission
 * during the observation makes the case INCONCLUSIVE.
 */
static int nagle_hold_one_octet(struct fixture *f)
{
    if (!fixture_init(f)) return -1;
    fixture_prepare_sender(f);
    f->conn->cc.win = 8;
    f->state.accept_arbitrary_payload = 1;
    /* iip recomputes the RTO from SRTT/RTTVAR (200 ms ticks) whenever it
     * queues a segment; (8 + 4 * 4) * 200 ms = 4.8 s keeps RTO out of the
     * observation window. */
    f->conn->rtt.srtt = 8;
    f->conn->rtt.rttvar = 4;
    if (!fixture_send_data(f, 1) || f->state.out_cnt != 1) return -1;
    free_output(&f->state);
    fake_clock_advance_ms(&f->state, 10);
    if (!fixture_send_data(f, 1) && test_ring_end(f->ws, &f->conn->tx_ring, 0) == NULL)
        return -1;
    if (f->state.out_cnt) return 0; /* not held */
    test_event_log_clear(&f->state);
    return 1;
}

/* An ACK-only segment acknowledging rcv_nxt, or any segment whose ACK field
 * acknowledges rcv_nxt. */
static int nagle_find_ack(struct fixture *f, uint32_t rcv_nxt, int pure_only)
{
    unsigned int i;
    for (i = 0; i < f->state.out_cnt; i++) {
        void *pkt = f->state.out[i];
        if (!PB_TCP_HDR_HAS_ACK(pkt) || PB_TCP_HDR_HAS_RST(pkt)) continue;
        if (ii_ntohl(PB_TCP(pkt)->ack_seq_be) != rcv_nxt) continue;
        if (pure_only && (PB_TCP_PAYLOAD_LEN(pkt) || PB_TCP_HDR_HAS_SYN(pkt) ||
                PB_TCP_HDR_HAS_FIN(pkt))) continue;
        return 1;
    }
    return 0;
}

/* RFC 9293 MUST-40: an ACK for received data must not be delayed by 0.5 s
 * or more -- also while Nagle holds our own small data. */
static enum result test_nagle_does_not_hold_ack(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[1] = { 'x' };
    uint32_t rcv_nxt;
    unsigned int elapsed;
    int held = nagle_hold_one_octet(&f);
    if (held < 0) { *why = "precondition: small writes were not emitted as expected"; return RESULT_ERROR; }
    if (!held) { *why = "Nagle did not hold the second small write; scenario not reachable"; return RESULT_SKIP; }
    fixture_incoming_spec(&f, &spec, f.conn->ack_seq, data, 1);
    spec.ack_seq = f.conn->acked_seq; /* does not acknowledge our octet */
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    rcv_nxt = f.conn->ack_seq;
    if (rcv_nxt != spec.seq + 1) { *why = "precondition: peer data not accepted"; return RESULT_ERROR; }
    for (elapsed = 0; ; elapsed += 50) {
        if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0)) {
            *why = "precondition: retransmission occurred before the ACK deadline"; return RESULT_INCONCLUSIVE;
        }
        if (nagle_find_ack(&f, rcv_nxt, 0)) return RESULT_PASS;
        if (elapsed >= 450) break;
        free_output(&f.state);
        fixture_advance_ms(&f, 50);
    }
    *why = "received data was not acknowledged within 0.5 s while Nagle held a small segment";
    return RESULT_FAIL;
}

/* RFC 5681 Section 4.2: an out-of-order segment SHOULD trigger an immediate
 * duplicate ACK; it only counts as one if it carries no data (Section 2). */
static enum result test_nagle_does_not_hold_dupack(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[1] = { 'x' };
    uint32_t rcv_nxt;
    int held = nagle_hold_one_octet(&f);
    if (held < 0) { *why = "precondition: small writes were not emitted as expected"; return RESULT_ERROR; }
    if (!held) { *why = "Nagle did not hold the second small write; scenario not reachable"; return RESULT_SKIP; }
    rcv_nxt = f.conn->ack_seq;
    fixture_incoming_spec(&f, &spec, rcv_nxt + 100, data, 1);
    spec.ack_seq = f.conn->acked_seq;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    if (f.conn->ack_seq != rcv_nxt) { *why = "precondition: out-of-order data advanced RCV.NXT"; return RESULT_ERROR; }
    if (!nagle_find_ack(&f, rcv_nxt, 1)) {
        *why = "no immediate data-less duplicate ACK for an out-of-order segment while Nagle held a small segment";
        return RESULT_TODO;
    }
    return RESULT_PASS;
}

/* Implementation profile: closing must not leave the held octet and the FIN
 * waiting for the outstanding ACK -- nothing can follow a FIN to coalesce. */
static enum result test_nagle_does_not_hold_fin(const char **why)
{
    struct fixture f;
    uint32_t held_seq;
    unsigned int i, elapsed;
    int data_seen = 0, fin_seen = 0;
    int held = nagle_hold_one_octet(&f);
    if (held < 0) { *why = "precondition: small writes were not emitted as expected"; return RESULT_ERROR; }
    if (!held) { *why = "Nagle did not hold the second small write; scenario not reachable"; return RESULT_SKIP; }
    held_seq = f.conn->acked_seq + 1;
    (void)test_api_close(f.ws, f.conn, &f.state);
    for (elapsed = 0; elapsed <= 200; elapsed += 50) {
        fixture_run_timers(&f);
        for (i = 0; i < f.state.out_cnt; i++) {
            void *pkt = f.state.out[i];
            uint32_t seq = ii_ntohl(PB_TCP(pkt)->seq_be);
            uint16_t len = PB_TCP_PAYLOAD_LEN(pkt);
            if (len && seq <= held_seq && held_seq < seq + len) data_seen = 1;
            if (PB_TCP_HDR_HAS_FIN(pkt) && seq + len == held_seq + 1) fin_seen = 1;
        }
        if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0)) {
            *why = "precondition: retransmission occurred during the observation"; return RESULT_INCONCLUSIVE;
        }
        if (data_seen && fin_seen) return RESULT_PASS;
        free_output(&f.state);
        fake_clock_advance_ms(&f.state, 50);
    }
    *why = data_seen ? "FIN was held after close while data was outstanding"
                     : "the held octet and FIN were not sent after close";
    return RESULT_FAIL;
}

static enum result test_rtt_first_sample_ticks(const char **why, unsigned ticks)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    if (!fixture_init(&f)) return RESULT_ERROR;
    const uint16_t port = ii_htons(29000);
    if (test_api_connect(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]), ii_htons(19000),
            f.peer_mac, ii_htonl(f.conn->dst_ip[0]), port, &f.state) == UINT16_MAX) return RESULT_ERROR;
    fixture_run_timers(&f);
    struct ii_tcp_conn *c = fixture_find_peer_port(&f, port);
    if (!c || !f.state.out_cnt) { *why = "active SYN missing"; return RESULT_FAIL; }
    uint32_t ack = ii_ntohl(PB_TCP(f.state.out[0])->seq_be) + 1;
    free_output(&f.state);
    /* Isolate first-sample estimation from initial RTO behavior.
     * Without this explicit precondition, iip's short initial RTO retransmits
     * the SYN before the sample, making Karn's rule apply. */
    c->rto_ms = 3000; c->rto_expire = f.ws->now_ms + 3000;
    /* iip exposes its estimator in 200ms ticks. Use an exact number of ticks. */
    for (unsigned i = 0; i < ticks; i++) {
        fixture_advance_ms(&f, 200);
    }
    if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0)) {
        *why = "SYN retransmitted: first-sample precondition failed"; return RESULT_INCONCLUSIVE;
    }
    fixture_incoming_spec(&f, &spec, 100, NULL, 0);
    spec.src_port_be = port; spec.dst_port_be = ii_htons(19000);
    spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK; spec.ack_seq = ack;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, c->state == II_TCP_STATE_ESTABLISHED &&
        c->rtt.srtt == ticks && c->rtt.rttvar == ticks / 2,
        "first RTT=%u ms: expected state=%u SRTT=%u RTTVAR=%u ticks, actual=%u/%u/%u",
        ticks * 200U, II_TCP_STATE_ESTABLISHED, ticks, ticks / 2,
        c->state, c->rtt.srtt, c->rtt.rttvar);
    return RESULT_PASS;
}
static enum result test_rtt_first_sample(const char **why)
{ return test_rtt_first_sample_ticks(why, 2); }
static enum result test_rtt_first_sample_long(const char **why)
{ return test_rtt_first_sample_ticks(why, 4); }

static enum result test_rtt_subsequent_sample(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    if (!fixture_init(&f)) return RESULT_ERROR;
    fixture_prepare_sender(&f);
    f.conn->rtt.srtt = 16; f.conn->rtt.rttvar = 8;
    if (!fixture_send_data(&f, 1)) return RESULT_FAIL;
    free_output(&f.state);
    for (unsigned i = 0; i < 8; i++) {
        fixture_advance_ms(&f, 200);
    }
    if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0)) {
        *why = "unexpected retransmission made the RTT observation ambiguous"; return RESULT_FAIL;
    }
    fixture_incoming_spec(&f, &spec, 0, NULL, 0);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    /* alpha=1/8, beta=1/4 profile: (7*16+8)/8=15, (3*8+abs(16-8))/4=8. */
    if (f.conn->acked_seq != f.conn->seq || f.conn->rtt.srtt != 15 || f.conn->rtt.rttvar != 8) {
        fprintf(stderr, "subsequent RTT=1600ms: SRTT=%u RTTVAR=%u (expected 15/8 ticks)\n",f.conn->rtt.srtt,f.conn->rtt.rttvar);
        *why = "RTT estimator failed the alpha=1/8 beta=1/4 profile"; return RESULT_FAIL;
    }
    free_output(&f.state);
    if (!fixture_send_data(&f, 1)) return RESULT_FAIL;
    if (f.conn->rto_ms < 9400) {
        *why = "RTO below SRTT + max(G,4*RTTVAR) after new sample"; return RESULT_FAIL;
    }
    return RESULT_PASS;
}

static enum result test_congestion_progress_profile(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    if (!fixture_init(&f)) return RESULT_ERROR;
    fixture_prepare_sender(&f);
    f.conn->cc.win = 8; f.conn->cc.ssthresh = 4;
    /* Saturated flights followed by full-MSS ACKs, above ssthresh. */
    const unsigned initial = f.conn->cc.win;
    for (unsigned round = 0; round < 8; round++) {
        test_event_log_clear(&f.state);
        unsigned flight = f.conn->cc.win;
        if (flight > 32) { *why = "profile flight exceeds harness capacity"; return RESULT_INCONCLUSIVE; }
        uint32_t ack = f.conn->acked_seq;
        for (unsigned j = 0; j < flight; j++) {
            if (!fixture_send_data(&f, f.conn->mss)) return RESULT_FAIL;
            free_output(&f.state);
        }
        for (unsigned j = 0; j < flight; j++) {
            ack += f.conn->mss;
            fixture_incoming_spec(&f, &spec, 0, NULL, 0);
            spec.ack_seq = ack;
            fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
            free_output(&f.state);
        }
        if (f.conn->cc.win > flight + 1) {
            *why = "Reno profile grew by more than one segment in a congestion-avoidance round";
            return RESULT_FAIL;
        }
    }
    if (f.conn->cc.win <= initial) {
        *why = "no congestion-avoidance growth after eight full flights"; return RESULT_FAIL;
    }
    return RESULT_PASS;
}

static enum result test_connection_address_lifetime(const char **why)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    struct passive_syn_ack hs;
    const uint16_t port = ii_htons(29002);
    if (!fixture_init(&f) || !fixture_passive_open(&f, port, -1, 0, 1, &hs)) return RESULT_ERROR;
    uint32_t local = ii_htonl(hs.conn->src_ip[0]);
    f.state.source_address_available = 1;
    f.state.selected_source_ip4_be = ii_htonl(0xc0000263U);
    f.conn = hs.conn;
    if (!fixture_send_data(&f, 1)) return RESULT_FAIL;
    for (unsigned phase = 0; phase < 3; phase++) {
        if (!f.state.out_cnt) { *why = "expected data, retransmission or FIN missing"; return RESULT_FAIL; }
        for (unsigned j = 0; j < f.state.out_cnt; j++) {
            void *pkt = f.state.out[j];
            if (PB_IP4(pkt)->proto == 6 && PB_IP4(pkt)->src_be != local) {
                *why = "connection changed source address during its lifetime"; return RESULT_FAIL;
            }
        }
        free_output(&f.state);
        if (phase == 0) {
            fixture_advance_ms(&f, (uint64_t)f.conn->rto_ms + 1);
        } else if (phase == 1) {
            fixture_incoming_spec(&f, &spec, 101, NULL, 0);
            fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
            free_output(&f.state);
            if (test_api_close(f.ws, f.conn, &f.state) == UINT16_MAX) return RESULT_ERROR;
            fixture_run_timers(&f);
        }
    }
    return RESULT_PASS;
}

static enum result test_harness_self_checks(const char **why)
{
    if (run_self_tests()) { *why = "harness self-test failed; inspect diagnostics"; return RESULT_ERROR; }
    return RESULT_PASS;
}

static enum result test_icmp_notification_0(const char **why)
{ return icmp_notification_case(0, 1, why); }

static enum result test_icmp_notification_1(const char **why)
{ return icmp_notification_case(1, 1, why); }

static enum result test_icmp_notification_2(const char **why)
{ return icmp_notification_case(2, 1, why); }

static enum result test_icmp_notification_3(const char **why)
{ return icmp_notification_case(3, 1, why); }

static enum result test_icmp_notification_4(const char **why)
{ return icmp_notification_case(4, 1, why); }

static enum result test_icmp_notification_5(const char **why)
{ return icmp_notification_case(5, 1, why); }

static enum result test_icmp_notification_6(const char **why)
{ return icmp_notification_case(6, 1, why); }

static enum result test_icmp_notification_7(const char **why)
{ return icmp_notification_case(7, 1, why); }

static enum result test_icmp_notification_8(const char **why)
{ return icmp_notification_case(8, 1, why); }

static enum result test_boundary_control(const char **why)
{ if (malformed_input_normal_controls()) return RESULT_PASS; *why = "control boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_checksum(const char **why)
{ if (malformed_checksum_cases()) return RESULT_PASS; *why = "checksum boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_truncated(const char **why)
{ if (truncated_packet_cases()) return RESULT_PASS; *why = "truncated boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_flags(const char **why)
{ if (invalid_flag_combination_cases()) return RESULT_PASS; *why = "flags boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_mss0(const char **why)
{ if (mss_boundary_case(0)) return RESULT_PASS; *why = "mss0 boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_mss1(const char **why)
{ if (mss_boundary_case(1)) return RESULT_PASS; *why = "mss1 boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_mssmax(const char **why)
{ if (mss_boundary_case(UINT16_MAX)) return RESULT_PASS; *why = "mssmax boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_boundary_payload(const char **why)
{ if (payload_length_boundary_cases()) return RESULT_PASS; *why = "payload boundary failed; see diagnostics"; return RESULT_FAIL; }

static enum result test_abort_after_fin_notification(const char **why)
{
    struct fixture normal, aborted;
    struct tcp_packet_spec spec;
    struct fixture *fs[2] = { &normal, &aborted };
    for (unsigned i = 0; i < 2; i++) {
        struct fixture *f = fs[i];
        if (!fixture_init(f)) return RESULT_ERROR;
        fixture_incoming_spec(f, &spec, 0, NULL, 0);
        spec.tcp_flags |= TEST_TCP_FIN;
        fixture_deliver(f, build_tcp_packet(&spec, &f->state));
        free_output(&f->state);
        if (f->state.close_wait.count != 1) return RESULT_FAIL;
        if (test_api_close(f->ws, f->conn, &f->state) == UINT16_MAX) return RESULT_ERROR;
        fixture_run_timers(f);
        free_output(&f->state);
        test_event_log_clear(&f->state);
        fixture_incoming_spec(f, &spec, 1, NULL, 0);
        if (i) spec.tcp_flags |= TEST_TCP_RST;
        fixture_deliver(f, build_tcp_packet(&spec, &f->state));
        fixture_run_timers(f);
        if (test_event_count(&f->state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) != 1) {
            *why = "close completion callback missing"; return RESULT_FAIL;
        }
    }
    /* The current callback only exposes handle, tuple and opaque. After peer
     * FIN, an ACK of our FIN and an RST produce the same application history. */
    const struct test_event *a = test_event_nth(&normal.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED, 0);
    const struct test_event *b = test_event_nth(&aborted.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED, 0);
    if (!memcmp(a->value, b->value, sizeof(a->value))) {
        *why = "normal FIN completion and RST after peer FIN expose identical callback information";
        return RESULT_FAIL;
    }
    return RESULT_PASS;
}

/* White-box sequence placement; payload order is checked by the callback. */
static enum result test_receive_wrap_case(const char **why, uint32_t start)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[] = { 0, 1, 2, 3 };
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.conn->seq_next_expected = start;
    f.conn->ack_seq = start;
    f.conn->ack_seq_xmitted = start;
    fixture_incoming_spec(&f, &spec, start + 2U, data + 2, 2);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 0,
        "out-of-order delivery: expected bytes=0, actual=%llu",
        (unsigned long long)f.state.payload_byte_count);
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, start, data, 2);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->seq_next_expected == start + 4U && f.state.payload_byte_count == 4,
        "gap filled: expected RCV.NXT=%u bytes=4, actual=%u/%llu", start + 4U,
        f.conn->seq_next_expected, (unsigned long long)f.state.payload_byte_count);
    free_output(&f.state);
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.state.payload_byte_count == 4 && f.conn->seq_next_expected == start + 4U,
        "duplicate: expected bytes=4 RCV.NXT=%u, actual=%llu/%u", start + 4U,
        (unsigned long long)f.state.payload_byte_count, f.conn->seq_next_expected);
    free_output(&f.state);
    fixture_incoming_spec(&f, &spec, start + 4U, NULL, 0);
    spec.tcp_flags |= TEST_TCP_FIN;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    TEST_REQUIRE(why, f.conn->state == II_TCP_STATE_CLOSE_WAIT &&
        f.conn->seq_next_expected == start + 5U && f.state.close_wait.count == 1,
        "FIN: expected state=%u RCV.NXT=%u notifications=1, actual=%u/%u/%u",
        II_TCP_STATE_CLOSE_WAIT, start + 5U, f.conn->state,
        f.conn->seq_next_expected, f.state.close_wait.count);
    return RESULT_PASS;
}
static enum result test_receive_wrap_control(const char **why)
{ return test_receive_wrap_case(why, 10000U); }
static enum result test_receive_wrap_boundary(const char **why)
{ return test_receive_wrap_case(why, UINT32_MAX - 1U); }

static enum result test_keepalive_clock_case(const char **why, uint32_t start)
{
    struct fixture f;
    if (!fixture_init(&f)) return RESULT_ERROR;
    fake_clock_set_ns(&f.state, (uint64_t)start * 1000000ULL);
    f.ws->now_ms = start;
    f.ws->timer.prev_fast = start;
    f.ws->timer.prev_slow = start;
    f.ws->timer.prev_very_slow = start;
    f.conn->keepalive_ts = start;
    test_set_keepalive(f.ws, f.conn, 1000U, &f.state);
    fixture_advance_ms(&f, 999);
    TEST_REQUIRE(why, f.state.out_cnt == 0,
        "keep-alive before deadline: expected packets=0, actual=%u", f.state.out_cnt);
    /* The 999 ms observation ran the slow timer; allow its next 500 ms tick. */
    fixture_advance_ms(&f, 500);
    TEST_REQUIRE(why, fixture_has_keepalive_probe(&f, f.conn->seq - 1U),
        "keep-alive after deadline: expected probe seq=%u, actual packets=%u clock=%u",
        f.conn->seq - 1U, f.state.out_cnt, f.ws->now_ms);
    return RESULT_PASS;
}
static enum result test_keepalive_clock_control(const char **why)
{ return test_keepalive_clock_case(why, 1000U); }
static enum result test_keepalive_clock_wrap(const char **why)
{ return test_keepalive_clock_case(why, UINT32_MAX - 500U); }

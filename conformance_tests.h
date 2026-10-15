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

static enum result test_source_route_api_available(const char **why)
{
    *why = "test route table has no binding to the native connect API; route configuration not exercised";
    return RESULT_INCONCLUSIVE;
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

static enum result test_rtt_first_sample(const char **why)
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
    /* iip exposes its estimator in 200ms ticks. Sample exactly two ticks. */
    for (unsigned i = 0; i < 2; i++) {
        fake_clock_advance_ms(&f.state, 200); fixture_run_timers(&f);
    }
    if (test_event_count(&f.state, TEST_EVENT_RETRANSMISSION, 0)) {
        *why = "SYN retransmitted: first-sample precondition failed"; return RESULT_INCONCLUSIVE;
    }
    fixture_incoming_spec(&f, &spec, 100, NULL, 0);
    spec.src_port_be = port; spec.dst_port_be = ii_htons(19000);
    spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK; spec.ack_seq = ack;
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    if (c->state != II_TCP_STATE_ESTABLISHED || c->rtt.srtt != 2 || c->rtt.rttvar != 1) {
        fprintf(stderr, "first RTT=400ms: state=%u SRTT=%u RTTVAR=%u (ticks; expected 2/1)\n", c->state,c->rtt.srtt,c->rtt.rttvar);
        *why = "first unambiguous RTT sample not initialized as R and R/2"; return RESULT_FAIL;
    }
    return RESULT_PASS;
}

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
        fake_clock_advance_ms(&f.state, 200); fixture_run_timers(&f);
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
            fake_clock_advance_ms(&f.state, (uint64_t)f.conn->rto_ms + 1);
            fixture_run_timers(&f);
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

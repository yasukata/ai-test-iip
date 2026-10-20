/* RFC 9293 3.10.7.4. The oracle uses RFC state/flag rules, never iip
 * transition or sequence-comparison functions. Direct state placement is a
 * white-box precondition; test_tcp_traces.h separately checks reachability. */
static int tcp_model_has_reply(struct fixture *f, uint16_t flags,
        uint32_t seq, uint32_t ack)
{
    for (unsigned i = 0; i < f->state.out_cnt; i++) {
        void *p = f->state.out[i];
        if (PB_IP4(p)->proto != 6) continue;
        /* PSH on an empty control segment has no effect on these rules. */
        uint16_t control = ii_ntohs(PB_TCP(p)->flags) & 0x37U;
        if (control == flags && ii_ntohl(PB_TCP(p)->seq_be) == seq &&
            (!(flags & TEST_TCP_ACK) || ii_ntohl(PB_TCP(p)->ack_seq_be) == ack) &&
            PB_TCP_PAYLOAD_LEN(p) == 0 && checksum_valid(p) && ip4_checksum_valid(p))
            return 1;
    }
    fprintf(stderr, "wire expectation: flags=%02x seq=%08x ack=%08x packets=%u\n",
        flags, seq, ack, f->state.out_cnt);
    for (unsigned i = 0; i < f->state.out_cnt; i++) {
        void *p = f->state.out[i];
        if (PB_IP4(p)->proto != 6) continue;
        fprintf(stderr, "  observed flags=%02x seq=%08x ack=%08x len=%u checksums=%d/%d\n",
            ii_ntohs(PB_TCP(p)->flags) & 0xffU, ii_ntohl(PB_TCP(p)->seq_be),
            ii_ntohl(PB_TCP(p)->ack_seq_be), PB_TCP_PAYLOAD_LEN(p), checksum_valid(p), ip4_checksum_valid(p));
    }
    return 0;
}

static void tcp_model_receive_at(struct fixture *f, uint32_t seq)
{
    f->conn->seq_next_expected = seq;
    f->conn->ack_seq = seq;
    f->conn->ack_seq_xmitted = seq;
    f->conn->ack_seq_pushed = seq;
}

/* Advertise through the stack's normal output path; decode only wire bytes.
 * These placed fixtures explicitly use a zero window-scale shift. */
static int tcp_model_advertise_window(struct fixture *f, uint32_t *window)
{
    free_output(&f->state);
    test_api_push(f->ws, f->conn, NULL, 0, 1, 0, 0, 0, NULL, 0, &f->state);
    fixture_run_timers(f);
    int found = 0;
    for (unsigned i = 0; i < f->state.out_cnt; i++) {
        void *p = f->state.out[i];
        if (PB_IP4(p)->proto == 6 && PB_TCP_HDR_HAS_ACK(p) &&
            ii_ntohl(PB_TCP(p)->ack_seq_be) == f->conn->seq_next_expected &&
            checksum_valid(p) && ip4_checksum_valid(p)) {
            *window = (uint32_t)ii_ntohs(PB_TCP(p)->win_be) << 0;
            found = 1;
        }
    }
    free_output(&f->state);
    return found;
}

/* One input per isolated registry case, so a failure does not hide other rows.
 * 0..3 retain the IDs from the initial working-tree implementation. */
static enum result tcp_model_input(const char **why, uint8_t initial,
        const char *name, unsigned int stimulus)
{
    struct fixture f;
    struct tcp_packet_spec spec;
    const uint8_t data[] = { 0, 1 };
    int peer_closed = initial == II_TCP_STATE_CLOSE_WAIT ||
        initial == II_TCP_STATE_CLOSING || initial == II_TCP_STATE_LAST_ACK ||
        initial == II_TCP_STATE_TIME_WAIT;
    /* The peer's FIN occupied 10000 in these placed states. */
    const uint32_t receive = peer_closed ? 10001 : 10000;
    uint8_t expected = initial;
    uint32_t next = receive, bytes = 0, fin_notifications = 0;
    int need_ack = 0, silent = 0;
    int receives = initial == II_TCP_STATE_ESTABLISHED ||
        initial == II_TCP_STATE_FIN_WAIT1 || initial == II_TCP_STATE_FIN_WAIT2;
    if (!fixture_init(&f)) return RESULT_ERROR;
    fixture_prepare_sender(&f);
    tcp_model_receive_at(&f, receive);
    uint32_t window;
    if (!tcp_model_advertise_window(&f, &window) || !window) {
        *why = "model setup: missing nonzero advertised receive window (scale=0)";
        return RESULT_INCONCLUSIVE;
    }
    /* Give FIN states a real outstanding local FIN. The state itself is
     * placed independently so a broken predecessor does not mask this row. */
    if (initial == II_TCP_STATE_FIN_WAIT1 || initial == II_TCP_STATE_FIN_WAIT2 ||
        initial == II_TCP_STATE_CLOSING || initial == II_TCP_STATE_LAST_ACK ||
        initial == II_TCP_STATE_TIME_WAIT) {
        TEST_REQUIRE(why, test_api_close(f.ws, f.conn, &f.state) == 0,
            "%s setup: local close failed", name);
        fixture_run_timers(&f);
        TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_FIN | TEST_TCP_ACK,
            f.conn->acked_seq, receive), "%s setup: local FIN missing", name);
        free_output(&f.state);
        if (initial == II_TCP_STATE_FIN_WAIT2 || initial == II_TCP_STATE_TIME_WAIT) {
            fixture_incoming_spec(&f, &spec, receive, NULL, 0);
            spec.ack_seq = f.conn->sent_seq;
            fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
            if (f.conn->acked_seq != f.conn->sent_seq ||
                test_ring_end(f.ws, &f.conn->sent_ring, 0)) {
                *why = "model setup: transmitted local FIN not acknowledged";
                return RESULT_INCONCLUSIVE;
            }
            free_output(&f.state);
        }
    }
    f.conn->state = initial;
    f.conn->time_wait_ts_ms = f.ws->now_ms;
    test_event_tcp_state_set(&f.state, f.conn, initial);
    test_event_log_clear(&f.state);
    uint32_t una = f.conn->acked_seq, snd_nxt = f.conn->sent_seq;
    fixture_incoming_spec(&f, &spec, receive, NULL, 0);
    spec.ack_seq = una;
    switch (stimulus) {
    case 0: /* No ACK: step five drops text, even in receive-capable states. */
    case 1:
        spec.tcp_flags = stimulus == 1 ? TEST_TCP_FIN : 0;
        spec.payload = data; spec.payload_len = sizeof(data);
        silent = 1;
        break;
    case 2:
        spec.seq = receive + window;
        spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
        silent = 1;
        break;
    case 3:
    case 11: /* RST takes precedence over FIN and text. */
        spec.tcp_flags = TEST_TCP_RST | TEST_TCP_ACK;
        if (stimulus == 11) {
            spec.tcp_flags |= TEST_TCP_FIN;
            spec.payload = data; spec.payload_len = sizeof(data);
        }
        expected = II_TCP_STATE_CLOSED;
        silent = 1;
        break;
    case 4: /* Data/duplicate ACK, including text after peer FIN. */
        spec.payload = data; spec.payload_len = sizeof(data);
        if (receives) { bytes = sizeof(data); next += bytes; need_ack = 1; }
        break;
    case 5: /* Future ACK must discard the entire segment, including FIN. */
        spec.ack_seq = snd_nxt + 1U;
        spec.tcp_flags |= TEST_TCP_FIN;
        spec.payload = data; spec.payload_len = sizeof(data);
        need_ack = receives || initial == II_TCP_STATE_CLOSE_WAIT ||
            initial == II_TCP_STATE_CLOSING;
        break;
    case 6: /* Stale ACK is not an acknowledgment of our FIN. */
        spec.ack_seq = una - 1U;
        break;
    case 7:
        spec.seq = receive + window;
        spec.payload = data; spec.payload_len = sizeof(data);
        need_ack = 1;
        break;
    case 8: /* New FIN while receiving; old duplicate FIN after peer close. */
        spec.tcp_flags |= TEST_TCP_FIN;
        if (receives) {
            next++;
            if (initial == II_TCP_STATE_ESTABLISHED) {
                expected = II_TCP_STATE_CLOSE_WAIT; fin_notifications = 1;
            } else if (initial == II_TCP_STATE_FIN_WAIT1)
                expected = II_TCP_STATE_CLOSING;
            else expected = II_TCP_STATE_TIME_WAIT;
        } else spec.seq--;
        need_ack = 1;
        break;
    case 9: /* Valid ACK of a transmitted local FIN (or duplicate ACK). */
        spec.ack_seq = snd_nxt;
        if (initial == II_TCP_STATE_FIN_WAIT1) expected = II_TCP_STATE_FIN_WAIT2;
        if (initial == II_TCP_STATE_CLOSING) expected = II_TCP_STATE_TIME_WAIT;
        if (initial == II_TCP_STATE_LAST_ACK) expected = II_TCP_STATE_CLOSED;
        break;
    case 12: /* Pure duplicate ACK must not acknowledge an outstanding FIN. */
        break;
    case 10: /* In-window SYN: allow RFC 793 reset OR RFC 5961 challenge ACK. */
        spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
        break;
    default: *why = "unknown state-model input"; return RESULT_ERROR;
    }
    fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
    if (stimulus == 10) {
        int reset = f.conn->state == II_TCP_STATE_CLOSED &&
            tcp_model_has_reply(&f, TEST_TCP_RST, spec.ack_seq, 0);
        int challenge = f.conn->state == initial &&
            f.conn->seq_next_expected == receive &&
            tcp_model_has_reply(&f, TEST_TCP_ACK, snd_nxt, receive);
        TEST_REQUIRE(why, (reset || challenge) && f.state.payload_byte_count == 0,
            "%s SYN: expected reset or challenge ACK; state=%u RCV.NXT=%u packets=%u",
            name, f.conn->state, f.conn->seq_next_expected, f.state.out_cnt);
        free_output(&f.state);
        return RESULT_PASS;
    }
    TEST_REQUIRE(why, f.conn->state == expected &&
        f.state.payload_byte_count == bytes && f.state.close_wait.count == fin_notifications,
        "%s input=%u: expected state=%u bytes=%u FIN callbacks=%u; actual=%u/%llu/%u",
        name, stimulus, expected, bytes, fin_notifications, f.conn->state,
        (unsigned long long)f.state.payload_byte_count, f.state.close_wait.count);
    if (expected != II_TCP_STATE_CLOSED) {
        uint32_t expected_una = stimulus == 9 ? snd_nxt : una;
        TEST_REQUIRE(why, f.conn->seq_next_expected == next && f.conn->acked_seq == expected_una,
            "%s input=%u: expected RCV.NXT=%u SND.UNA=%u; actual=%u/%u",
            name, stimulus, next, expected_una, f.conn->seq_next_expected, f.conn->acked_seq);
        TEST_REQUIRE(why, test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 0,
            "%s input=%u: unexpected CLOSED callback", name, stimulus);
    } else {
        TEST_REQUIRE(why, test_event_count(&f.state, TEST_EVENT_CALLBACK, TEST_CALLBACK_CLOSED) == 1 &&
            !test_ring_end(f.ws, &f.conn->sent_ring, 0),
            "%s input=%u: expected one CLOSED callback and drained retransmission queue", name, stimulus);
    }
    if (need_ack) {
        /* Permit delayed ACK for data. Control/error replies are observed
         * without advancing timers that might retransmit the local FIN. */
        if (stimulus == 4 && !f.state.out_cnt) fixture_advance_ms(&f, 400);
        TEST_REQUIRE(why, tcp_model_has_reply(&f, TEST_TCP_ACK, snd_nxt, next),
            "%s input=%u: expected ACK seq=%u ack=%u; packets=%u",
            name, stimulus, snd_nxt, next, f.state.out_cnt);
    }
    if (silent) TEST_REQUIRE(why, f.state.out_cnt == 0,
        "%s input=%u: expected silent discard/reset; packets=%u", name, stimulus, f.state.out_cnt);
    free_output(&f.state);
    return RESULT_PASS;
}

static enum result test_model_established_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 0); }

static enum result test_model_established_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 1); }

static enum result test_model_established_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 2); }

static enum result test_model_established_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 3); }

static enum result test_model_fin_wait1_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 0); }

static enum result test_model_fin_wait1_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 1); }

static enum result test_model_fin_wait1_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 2); }

static enum result test_model_fin_wait1_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 3); }

static enum result test_model_fin_wait2_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 0); }

static enum result test_model_fin_wait2_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 1); }

static enum result test_model_fin_wait2_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 2); }

static enum result test_model_fin_wait2_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 3); }

static enum result test_model_close_wait_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 0); }

static enum result test_model_close_wait_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 1); }

static enum result test_model_close_wait_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 2); }

static enum result test_model_close_wait_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 3); }

static enum result test_model_closing_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 0); }

static enum result test_model_closing_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 1); }

static enum result test_model_closing_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 2); }

static enum result test_model_closing_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 3); }

static enum result test_model_last_ack_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 0); }

static enum result test_model_last_ack_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 1); }

static enum result test_model_last_ack_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 2); }

static enum result test_model_last_ack_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 3); }

static enum result test_model_time_wait_0(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 0); }

static enum result test_model_time_wait_1(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 1); }

static enum result test_model_time_wait_2(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 2); }

static enum result test_model_time_wait_3(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 3); }

static enum result test_model_established_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 4); }

static enum result test_model_established_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 5); }

static enum result test_model_established_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 6); }

static enum result test_model_established_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 7); }

static enum result test_model_established_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 8); }

static enum result test_model_established_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 9); }

static enum result test_model_established_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 10); }

static enum result test_model_established_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 11); }

static enum result test_model_fin_wait1_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 4); }

static enum result test_model_fin_wait1_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 5); }

static enum result test_model_fin_wait1_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 6); }

static enum result test_model_fin_wait1_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 7); }

static enum result test_model_fin_wait1_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 8); }

static enum result test_model_fin_wait1_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 9); }

static enum result test_model_fin_wait1_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 10); }

static enum result test_model_fin_wait1_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 11); }

static enum result test_model_fin_wait2_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 4); }

static enum result test_model_fin_wait2_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 5); }

static enum result test_model_fin_wait2_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 6); }

static enum result test_model_fin_wait2_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 7); }

static enum result test_model_fin_wait2_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 8); }

static enum result test_model_fin_wait2_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 9); }

static enum result test_model_fin_wait2_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 10); }

static enum result test_model_fin_wait2_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 11); }

static enum result test_model_close_wait_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 4); }

static enum result test_model_close_wait_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 5); }

static enum result test_model_close_wait_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 6); }

static enum result test_model_close_wait_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 7); }

static enum result test_model_close_wait_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 8); }

static enum result test_model_close_wait_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 9); }

static enum result test_model_close_wait_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 10); }

static enum result test_model_close_wait_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 11); }

static enum result test_model_closing_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 4); }

static enum result test_model_closing_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 5); }

static enum result test_model_closing_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 6); }

static enum result test_model_closing_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 7); }

static enum result test_model_closing_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 8); }

static enum result test_model_closing_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 9); }

static enum result test_model_closing_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 10); }

static enum result test_model_closing_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 11); }

static enum result test_model_last_ack_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 4); }

static enum result test_model_last_ack_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 5); }

static enum result test_model_last_ack_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 6); }

static enum result test_model_last_ack_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 7); }

static enum result test_model_last_ack_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 8); }

static enum result test_model_last_ack_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 9); }

static enum result test_model_last_ack_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 10); }

static enum result test_model_last_ack_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 11); }

static enum result test_model_time_wait_4(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 4); }

static enum result test_model_time_wait_5(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 5); }

static enum result test_model_time_wait_6(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 6); }

static enum result test_model_time_wait_7(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 7); }

static enum result test_model_time_wait_8(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 8); }

static enum result test_model_time_wait_9(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 9); }

static enum result test_model_time_wait_10(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 10); }

static enum result test_model_time_wait_11(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 11); }

static enum result test_model_established_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_ESTABLISHED, "ESTABLISHED", 12); }

static enum result test_model_fin_wait1_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1", 12); }

static enum result test_model_fin_wait2_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2", 12); }

static enum result test_model_close_wait_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT", 12); }

static enum result test_model_closing_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_CLOSING, "CLOSING", 12); }

static enum result test_model_last_ack_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_LAST_ACK, "LAST-ACK", 12); }

static enum result test_model_time_wait_12(const char **why)
{ return tcp_model_input(why, II_TCP_STATE_TIME_WAIT, "TIME-WAIT", 12); }

/* Native-handshake diagnostic reproducers outside the coverage registry.
 * Link the unchanged integration/backend and use native OPEN/RUN/CLOSE plus
 * a scripted wire peer. No connection state or sequence is assigned here.
 * Internal fields are printed only as diagnostics, never as wire expectations.
 */
#define main baseline_suite_main
#include "../main.c"
#undef main

static const char *probe_name;

static int probe_open(struct oracle_peer *p, uint32_t start, uint32_t *window)
{
    memset(p, 0, sizeof(*p));
    p->ws = calloc(1, sizeof(*p->ws));
    if (!p->ws) return fixture_setup_failed("probe workspace allocation failed");
    test_workspace_init(p->ws);
    p->state.local_mac[0] = 2;
    p->state.local_ip4_be = htonl(0xc0000201U);
    p->state.use_fake_clock = p->state.quiet_payload = 1;
    p->state.accept_arbitrary_payload = p->state.oracle.enabled = 1;
    p->state.now_ns = UINT64_C(1000000000);
    if (!oracle_run(p, NULL)) return 0;
    uint8_t peer_mac[6] = {4};
    TEST_CONDITION(iip_tcp_ipv4_ethernet_connect(p->ws, p->state.local_mac,
        p->state.local_ip4_be, htons(15000), peer_mac, htonl(0xc6336402U),
        htons(25000), NULL, 0, NULL, 0, &p->state) == 0, "native OPEN failed");
    TEST_CONDITION(oracle_run(p, NULL) && p->state.out_cnt == 1,
        "expected one native SYN");
    struct oracle_segment syn;
    if (!oracle_parse(p->state.out[0], &syn)) return 0;
    TEST_CONDITION((syn.flags & 0x17) == 2 && !syn.length, "invalid SYN");
    p->tx = syn.seq + 1U; p->rx = start;
    free_output(&p->state);
    TEST_CONDITION(oracle_input(p, start - 1U, 0x12, NULL, 0, 0) &&
        p->state.oracle.connected == 1 && p->state.out_cnt == 1,
        "native SYN+ACK/CONNECTED failed");
    const uint8_t *b = iip_ops_pkt_get_data(p->state.out[0], NULL);
    /* The scripted SYN+ACK has no window-scale option. */
    *window = oracle_u16(b + 14 + (b[14] & 15) * 4 + 14);
    TEST_CONDITION(*window != 0, "missing advertised receive window");
    return oracle_control(p, 0x10);
}

static void probe_observe(struct oracle_peer *p, const char *step)
{
    const struct ii_tcp_conn *c = &p->ws->tcp_conns.array[p->state.oracle.conn_id];
    fprintf(stderr, "PROBE %s: state=%u rcv_nxt=%u una=%u nxt=%u "
        "bytes=%zu eof=%u closed=%u outputs=%u\n", step, c->state,
        c->seq_next_expected, c->acked_seq, c->sent_seq,
        p->state.oracle.length, p->state.oracle.eof, p->state.oracle.closed,
        p->state.out_cnt);
    for (unsigned i = 0; i < p->state.out_cnt; i++) {
        struct oracle_segment s;
        if (oracle_parse(p->state.out[i], &s))
            fprintf(stderr, "PROBE wire: flags=%02x seq=%u ack=%u len=%u\n",
                s.flags, s.seq, s.ack, s.length);
    }
}

static enum result probe_run(const char **why)
{
    struct oracle_peer p;
    uint32_t window = 0, start = 10000;
    const uint8_t data[] = {0,1,2,3,4,5,6,7,8};
    if (!strcmp(probe_name, "pending-zero")) start = 0;
    if (!strcmp(probe_name, "pending-wrap")) start = UINT32_MAX;
    TEST_REQUIRE(why, probe_open(&p, start, &window), "native handshake failed");
    if (!strncmp(probe_name, "pending-", 8)) {
        if (strcmp(probe_name, "pending-control")) {
            test_step("native pending S+7");
            TEST_REQUIRE(why, oracle_input(&p, start + 7U, 0x10, data + 7, 1, 0) &&
                oracle_received(&p, data, 0), "out-of-order byte delivered early");
            free_output(&p.state);
        }
        test_step("native covering S..S+7");
        TEST_REQUIRE(why, oracle_input(&p, start, 0x10, data, 8, 0) &&
            oracle_received(&p, data, 8), "covering segment not delivered once");
        TEST_REQUIRE(why, oracle_input(&p, start + 8U, 0x10, data + 8, 1, 0) &&
            oracle_received(&p, data, 9), "fresh byte after coverage lost");
        p.rx += 9;
    } else {
        /* Every non-crash probe first demonstrates valid application input. */
        TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, data, 4, 0) &&
            oracle_received(&p, data, 4), "ESTABLISHED positive control failed");
        p.rx += 4;
        p.state.now_ns += UINT64_C(400000000);
        TEST_REQUIRE(why, oracle_run(&p, NULL) && oracle_control(&p, 0x10),
            "positive control cumulative ACK missing");
        if (!strncmp(probe_name, "fin-wait", 8)) {
            TEST_REQUIRE(why, iip_tcp_close(p.ws, p.state.oracle.conn_id, &p.state) == 0 &&
                oracle_run(&p, NULL) && oracle_control(&p, 0x11), "native CLOSE/FIN failed");
            /* FIN-WAIT1 leaves FIN unacknowledged; FIN-WAIT2 ACKs the wire FIN. */
            if (!strcmp(probe_name, "fin-wait2")) {
                p.tx++;
                TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, NULL, 0, 0), "FIN ACK failed");
            }
            probe_observe(&p, "before post-CLOSE receive");
            TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, data + 4, 4, 0), "data input failed");
            probe_observe(&p, "after post-CLOSE receive");
            TEST_REQUIRE(why, oracle_received(&p, data, 8),
                "native post-CLOSE receive: expected 8 total bytes, actual=%zu", p.state.oracle.length);
            p.rx += 4;
        } else if (!strcmp(probe_name, "control")) {
            TEST_REQUIRE(why, oracle_run(&p, NULL) && p.state.out_cnt == 0,
                "idle control unexpectedly emitted a packet");
        } else if (!strncmp(probe_name, "rst-", 4)) {
            uint32_t offset = !strcmp(probe_name, "rst-outside") ? window : UINT32_C(0x10000000);
            TEST_REQUIRE(why, oracle_input(&p, p.rx + offset, 0x14, NULL, 0, 0), "RST input failed");
            probe_observe(&p, "outside-window RST");
            TEST_REQUIRE(why, !p.state.out_cnt && !p.state.oracle.closed,
                "outside-window RST was not silently discarded");
        } else if (!strcmp(probe_name, "syn")) {
            TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x12, NULL, 0, 0), "SYN input failed");
            probe_observe(&p, "synchronized SYN");
            int response = 0;
            for (unsigned i = 0; i < p.state.out_cnt; i++) {
                struct oracle_segment s;
                if (!oracle_parse(p.state.out[i], &s)) return RESULT_FAIL;
                if (!s.length && (((s.flags & 0x17) == 4 && s.seq == p.tx &&
                    p.state.oracle.closed == 1) || ((s.flags & 0x17) == 0x10 &&
                    s.seq == p.tx && s.ack == p.rx && !p.state.oracle.closed))) response = 1;
            }
            TEST_REQUIRE(why, response, "synchronized SYN: missing reset/challenge ACK");
            if (p.state.oracle.closed) { free_output(&p.state); free(p.ws); return RESULT_PASS; }
        } else {
            unsigned flags = !strncmp(probe_name, "noack-", 6) ? 0 : 0x10;
            if (strstr(probe_name, "fin")) flags |= 1;
            uint32_t tx = p.tx;
            if (!strncmp(probe_name, "future-", 7)) p.tx++;
            TEST_REQUIRE(why, oracle_input(&p, p.rx, flags, data + 4, 2, 0), "negative input failed");
            p.tx = tx;
            probe_observe(&p, "after negative input");
            TEST_REQUIRE(why, oracle_received(&p, data, 4) && !p.state.oracle.eof && !p.state.oracle.closed,
                "discard violated: bytes=%zu EOF=%u closed=%u", p.state.oracle.length,
                p.state.oracle.eof, p.state.oracle.closed);
            free_output(&p.state);
            TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, data + 4, 2, 0), "recovery input failed");
            probe_observe(&p, "valid recovery at original sequence");
            TEST_REQUIRE(why, oracle_received(&p, data, 6),
                "discard advanced receive sequence: valid recovery expected 6 bytes, actual=%zu",
                p.state.oracle.length);
            p.rx += 2;
        }
    }
    TEST_REQUIRE(why, oracle_reset(&p), "native reset cleanup failed");
    return RESULT_PASS;
}

int main(int argc, char **argv)
{
    const char *names[] = {"control", "pending-control", "pending-zero", "pending-wrap", "pending-ordinary",
        "fin-wait1", "fin-wait2", "noack-data", "noack-fin", "future-data", "future-fin",
        "rst-outside", "rst-far-outside", "syn"};
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (unsigned i = 0; i < ARRAY_LENGTH(names); i++) puts(names[i]);
        return 0;
    }
    int found = 0;
    if (argc == 2) for (unsigned i = 0; i < ARRAY_LENGTH(names); i++)
        if (!strcmp(argv[1], names[i])) found = 1;
    if (!found) { fputs("usage: baseline-probes --list | PROBE\n", stderr); return 2; }
    probe_name = argv[1];
    const char *why = NULL;
    enum result r = run_isolated_test(probe_run, &why);
    printf("{\"probe\":"); json_string(stdout, probe_name);
    printf(",\"status\":"); json_string(stdout, result_name(r));
    printf(",\"execution\":"); json_string(stdout, test_execution_name());
    printf(",\"reason\":"); json_string(stdout, why ? why : "");
    puts("}");
    return r == RESULT_PASS ? 0 : r == RESULT_ERROR ? 2 : 1;
}

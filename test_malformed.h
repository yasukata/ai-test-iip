/* Phase 4: byte-oriented input construction, exact backing lengths, and
 * recovery observations. No input validation adapter is enabled here.
 * Each registered case runs in the existing process-isolated runner. */

static void malformed_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

/* Independent byte sum: never infer a readable range from mutated fields. */
static uint16_t malformed_sum(const uint8_t *p, size_t n, uint32_t sum)
{
    for (size_t i = 0; i < n; i += 2)
        sum += ((uint32_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535U) + (sum >> 16);
    return (uint16_t)~sum;
}

static void malformed_ip_sum(uint8_t *p, unsigned ihl)
{
    p[24] = p[25] = 0;
    malformed_u16(p + 24, malformed_sum(p + 14, ihl, 0));
}

static void malformed_transport_sum(uint8_t *p, unsigned ihl, unsigned n)
{
    uint8_t *ip = p + 14, *l4 = ip + ihl;
    unsigned at = ip[9] == 6 ? 16 : 6;
    l4[at] = l4[at + 1] = 0;
    uint32_t sum = (uint16_t)~malformed_sum(ip + 12, 8, 0);
    uint16_t value = malformed_sum(l4, n, sum + ip[9] + n);
    malformed_u16(l4 + at, value ? value : 65535);
}

/* Returns the physical frame length; caller supplies storage. Payload follows
 * the harness's independent ascending-byte application oracle. */
static size_t malformed_frame(struct fixture *f, uint8_t *p, uint8_t proto,
        unsigned ihl, unsigned thl, unsigned payload)
{
    size_t n = 14U + ihl + thl + payload;
    memset(p, 0, n);
    memcpy(p, f->local_mac, 6); memcpy(p + 6, f->peer_mac, 6);
    malformed_u16(p + 12, 0x0800);
    p[14] = 0x40 | (ihl / 4); p[22] = 64; p[23] = proto;
    malformed_u16(p + 16, (uint16_t)(n - 14));
    malformed_u16(p + 18, 0x4567);
    uint32_t src = ii_htonl(f->conn->dst_ip[0]);
    uint32_t dst = ii_htonl(f->conn->src_ip[0]);
    memcpy(p + 26, &src, 4); memcpy(p + 30, &dst, 4);
    uint8_t *t = p + 14 + ihl;
    malformed_u16(t, f->conn->dst_port);
    malformed_u16(t + 2, f->conn->src_port);
    if (proto == 6) {
        uint32_t seq = ii_htonl(f->conn->seq_next_expected);
        uint32_t ack = ii_htonl(f->conn->seq);
        memcpy(t + 4, &seq, 4); memcpy(t + 8, &ack, 4);
        t[12] = (uint8_t)((thl / 4) << 4); t[13] = TEST_TCP_ACK;
        malformed_u16(t + 14, 65535);
    } else {
        malformed_u16(t + 4, (uint16_t)(thl + payload));
    }
    for (unsigned i = 0; i < payload; i++)
        t[thl + i] = (uint8_t)(f->state.next_payload + i);
    malformed_transport_sum(p, ihl, thl + payload);
    malformed_ip_sum(p, ihl);
    return n;
}

static void *malformed_exact_packet(const uint8_t *bytes, uint16_t n)
{
    void *pkt = test_pkt_alloc_capacity(n);
    memcpy(iip_ops_pkt_get_data(pkt, NULL), bytes, n);
    iip_ops_pkt_set_len(pkt, n, NULL);
    return pkt;
}

static unsigned malformed_udp_count(struct fixture *f)
{
    return test_event_count(&f->state, TEST_EVENT_CALLBACK,
            TEST_CALLBACK_UDP_PAYLOAD);
}

static int malformed_state_init(struct fixture *f, unsigned state);

struct malformed_recovery {
    uint64_t bytes;
    unsigned chunks, udp_count, udp_len, udp_first;
    uint32_t seq_delta;
    uint8_t state;
};

static struct malformed_recovery malformed_probe(struct fixture *f)
{
    struct malformed_recovery r = {0};
    unsigned chunks = f->state.payload_chunk_count, udp = malformed_udp_count(f);
    uint64_t bytes = f->state.payload_byte_count;
    uint32_t seq = f->conn->seq_next_expected;
    uint8_t valid[80];
    unsigned len = malformed_frame(f, valid, 6, 20, 20, 4);
    fixture_deliver(f, malformed_exact_packet(valid, len));
    r.chunks = f->state.payload_chunk_count - chunks;
    r.bytes = f->state.payload_byte_count - bytes;
    r.seq_delta = f->conn->seq_next_expected - seq;
    r.state = f->conn->state;
    len = malformed_frame(f, valid, 17, 20, 8, 4);
    fixture_deliver(f, malformed_exact_packet(valid, len));
    const struct test_event *e = test_event_nth(&f->state,
        TEST_EVENT_CALLBACK, TEST_CALLBACK_UDP_PAYLOAD, udp);
    r.udp_count = malformed_udp_count(f) - udp;
    if (e) {
        r.udp_len = e->value[2];
        r.udp_first = (uint8_t)(e->value[3] - f->state.next_payload);
    }
    return r;
}

static bool malformed_control_ok(struct malformed_recovery r)
{
    return r.bytes == 4 && r.chunks == 1 && r.seq_delta == 4 &&
        r.udp_count == 1 && r.udp_len == 4 && !r.udp_first;
}

static const char *malformed_control_id(unsigned state)
{
    return state == II_TCP_STATE_FIN_WAIT1 ? "MAL-VALID-FIN-WAIT1" :
        state == II_TCP_STATE_FIN_WAIT2 ? "MAL-VALID-FIN-WAIT2" : "MAL-VALID-ESTABLISHED";
}

/* Always try recovery after a nonfatal mismatch as well. Short-circuiting on
 * unwanted delivery would conceal whether the next valid packet survived. */
static enum result malformed_observe(struct fixture *f, const uint8_t *p,
        uint16_t n, bool silent, bool may_reset, const char **why)
{
    uint32_t original_seq = f->conn->seq_next_expected;
    uint8_t original_state = f->conn->state;
    struct fixture clean;
    if (!malformed_state_init(&clean, original_state)) return RESULT_ERROR;
    struct malformed_recovery control = malformed_probe(&clean);
    free_output(&clean.state);
    free(clean.ws);
    fprintf(stderr, "clean control %s: bytes=%llu chunks=%u seq_delta=%u state=%u UDP=%u/%u/%u valid=%u\n",
        malformed_control_id(original_state), (unsigned long long)control.bytes,
        control.chunks, control.seq_delta, control.state, control.udp_count,
        control.udp_len, control.udp_first, malformed_control_ok(control));
    fixture_deliver(f, malformed_exact_packet(p, n));
    bool rejected = f->state.payload_chunk_count == 0 && !malformed_udp_count(f);
    bool silence = !silent || f->state.out_cnt == 0;
    /* RFC 9293 MUST-7 permits graceful handling; SHOULD-7 recommends reset.
     * A reset is allowed for illegal options, with recovery on a fresh tuple
     * in the SAME workspace. Other malformed families must preserve TCP. */
    bool reset = f->conn->state == II_TCP_STATE_CLOSED;
    bool state_ok = (may_reset && reset) ||
        (f->conn->state == original_state && f->conn->seq_next_expected == original_seq);
    if (reset && may_reset) {
        uint32_t id;
        if (ii_alloc_tcp_conn(&f->ws->tcp_conns, &id) != IIP_ERR_OK)
            return RESULT_ERROR;
        f->conn = &f->ws->tcp_conns.array[id];
        test_api_conn_init(f->ws, f->conn, f->local_mac, ii_htonl(0xc0000201U),
            ii_htons(10001), f->peer_mac, ii_htonl(0xc6336402U),
            ii_htons(20001), II_TCP_STATE_ESTABLISHED, &f->state);
        f->conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
    }
    struct malformed_recovery actual = malformed_probe(f);
    bool equal = actual.bytes == control.bytes && actual.chunks == control.chunks &&
        actual.seq_delta == control.seq_delta && actual.state == control.state &&
        actual.udp_count == control.udp_count && actual.udp_len == control.udp_len &&
        actual.udp_first == control.udp_first;
    /* RFC 9293 3.10.7.4 describes per-state processing; the robustness
     * recovery profile compares like states. A broken clean fixture is not
     * evidence that malformed input damaged it. Keep input violations FAIL. */
    TEST_REQUIRE(why, rejected && silence && state_ok && equal,
        "frame=%u: no unexpected delivery=%u silent=%u state preserved=%u; "
        "recovery equals clean=%u; clean %s valid=%u TCP=%llu/%u/%u UDP=%u/%u",
        n, rejected, silence, state_ok, equal, malformed_control_id(original_state),
        malformed_control_ok(control), (unsigned long long)control.bytes,
        control.chunks, control.seq_delta, control.udp_count, control.udp_len);
    if (!malformed_control_ok(control)) {
        snprintf(test_failure_detail, sizeof(test_failure_detail),
            "recovery equals clean control, but %s fails: TCP bytes=%llu chunks=%u seq_delta=%u UDP=%u/%u",
            malformed_control_id(original_state), (unsigned long long)control.bytes,
            control.chunks, control.seq_delta, control.udp_count, control.udp_len);
        *why = test_failure_detail;
        return RESULT_INCONCLUSIVE;
    }
    return RESULT_PASS;
}

static enum result malformed_truncate(unsigned proto, unsigned n,
        bool nested, const char **why)
{
    struct fixture f;
    uint8_t p[80];
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.state.quiet_payload = 1;
    malformed_frame(&f, p, proto, 20, proto == 6 ? 20 : 8, 1);
    /* Nested truncation passes IPv4 validation and reaches the L4 parser. */
    if (nested) {
        malformed_u16(p + 16, n - 14);
        malformed_ip_sum(p, 20);
    }
    return malformed_observe(&f, p, n, true, false, why);
}

enum malformed_field {
    MAL_IP_TOTAL, MAL_IP_IHL, MAL_TCP_OFFSET, MAL_UDP_LENGTH,
    MAL_IP_CHECKSUM, MAL_TCP_CHECKSUM, MAL_UDP_CHECKSUM,
    MAL_FRAGMENT, MAL_COMBINED, MAL_UDP_EMPTY_LENGTH
};
static enum result malformed_field_case(enum malformed_field field,
        unsigned value, const char **why)
{
    struct fixture f;
    uint8_t p[128];
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.state.quiet_payload = 1;
    unsigned proto = field == MAL_UDP_LENGTH || field == MAL_UDP_CHECKSUM ||
        field == MAL_UDP_EMPTY_LENGTH ? 17 : 6;
    unsigned n = malformed_frame(&f, p, proto, 20, proto == 6 ? 20 : 8,
        field == MAL_UDP_EMPTY_LENGTH ? 0 : 8);
    switch (field) {
    case MAL_IP_TOTAL: malformed_u16(p + 16, value); break;
    case MAL_IP_IHL: p[14] = 0x40 | value; break;
    case MAL_TCP_OFFSET:
        p[46] = value << 4;
        malformed_transport_sum(p, 20, n - 34); break;
    case MAL_UDP_LENGTH:
    case MAL_UDP_EMPTY_LENGTH:
        malformed_u16(p + 38, value);
        /* UDP checksum zero is legal in IPv4; isolate length validation. */
        p[40] = p[41] = 0; break;
    case MAL_TCP_CHECKSUM: p[50] ^= 1; break;
    case MAL_UDP_CHECKSUM: p[40] ^= 1; break;
    case MAL_IP_CHECKSUM: break;
    case MAL_FRAGMENT:
        malformed_u16(p + 20, value);
        /* Nonfinal payload 28 is not a multiple of 8. Other offsets
         * exercise 13-bit offset * 8 + payload boundary arithmetic. */
        break;
    case MAL_COMBINED:
        p[14] = 0x4f; malformed_u16(p + 16, 65535);
        p[46] = 0xf0; malformed_u16(p + 20, 0x3fff);
        p[50] ^= 1; break;
    }
    /* The backing scratch is large enough for IHL=15. The exact receive
     * allocation is made only after checksum construction has finished. */
    if (field == MAL_IP_IHL) memset(p + n, 0, sizeof(p) - n);
    malformed_ip_sum(p, field == MAL_IP_IHL && value >= 5 ? value * 4 : 20);
    if (field == MAL_IP_CHECKSUM) p[24] ^= 1;
    return malformed_observe(&f, p, n, true, false, why);
}

static const uint8_t malformed_options[][4] = {
    { 253, 0, 0, 0 }, { 253, 1, 0, 0 }, { 253, 5, 0, 0 },
    { 253, 255, 0, 0 }, { 1, 1, 1, 253 },
    { 253, 2, 2, 0 }, /* valid unknown option followed by malformed MSS */
    { 2, 3, 0, 0 }, { 3, 2, 0, 0 }, { 8, 4, 0, 0 },
    { 5, 3, 0, 0 }, { 4, 3, 0, 0 }
};
static enum result malformed_option_case(unsigned index, const char **why)
{
    struct fixture f;
    uint8_t p[80];
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.state.quiet_payload = 1;
    unsigned n = malformed_frame(&f, p, 6, 20, 24, 1);
    memcpy(p + 54, malformed_options[index], 4);
    malformed_transport_sum(p, 20, n - 34);
    return malformed_observe(&f, p, n, false, true, why);
}

/* Positive controls: true protocol header maxima, minimum legal datagrams,
 * and checksum-disabled UDP. They prevent blanket rejection from passing. */
static enum result malformed_valid_case(unsigned variant, const char **why)
{
    struct fixture f;
    uint8_t p[160];
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.state.quiet_payload = 1;
    unsigned proto = variant >= 2 ? 17 : 6;
    unsigned ihl = variant == 1 ? 60 : 20;
    unsigned thl = proto == 17 ? 8 : variant == 1 ? 60 : 20;
    unsigned payload = variant == 1 || variant == 3 ? 4 : 0;
    unsigned n = malformed_frame(&f, p, proto, ihl, thl, payload);
    if (variant == 3) p[40] = p[41] = 0;
    fixture_deliver(&f, malformed_exact_packet(p, n));
    const struct test_event *e = test_event_nth(&f.state,
        TEST_EVENT_CALLBACK, TEST_CALLBACK_UDP_PAYLOAD, 0);
    TEST_REQUIRE(why, proto == 6 ? f.state.payload_byte_count == payload &&
        f.state.payload_chunk_count == !!payload :
        malformed_udp_count(&f) == 1 && e && e->value[2] == payload,
        "valid variant=%u rejected or payload length differs (TCP=%llu UDP=%u)",
        variant, (unsigned long long)f.state.payload_byte_count, malformed_udp_count(&f));
    return RESULT_PASS;
}

/* A 65535-byte IPv4 datagram cannot fit in a uint16 Ethernet frame length.
 * Reassemble two large, exact-size fragments instead. This tests the legal
 * protocol maximum, not the old backend's 2048-byte allocation ceiling. */
static enum result malformed_maximum(unsigned proto, const char **why)
{
    struct fixture f;
    if (!fixture_init(&f)) return RESULT_ERROR;
    f.state.quiet_payload = 1;
    unsigned thl = proto == 6 ? 20 : 8;
    uint8_t *whole = malloc(65535U + 14);
    uint8_t *frag = malloc(34U + 32760);
    if (!whole || !frag) { free(whole); free(frag); return RESULT_ERROR; }
    malformed_frame(&f, whole, proto, 20, thl, 65515 - thl);
    for (unsigned off = 0; off < 65515;) {
        unsigned part = off ? 65515 - off : 32760;
        memcpy(frag, whole, 34); memcpy(frag + 34, whole + 34 + off, part);
        malformed_u16(frag + 16, 20 + part);
        malformed_u16(frag + 20, (off / 8) | (off ? 0 : 0x2000));
        malformed_ip_sum(frag, 20);
        fixture_deliver(&f, malformed_exact_packet(frag, 34 + part));
        off += part;
    }
    free(whole); free(frag);
    const struct test_event *e = test_event_nth(&f.state,
        TEST_EVENT_CALLBACK, TEST_CALLBACK_UDP_PAYLOAD, 0);
    bool delivered = proto == 6 ? f.state.payload_byte_count == 65495 :
        malformed_udp_count(&f) == 1 && e && e->value[2] == 65507;
    TEST_REQUIRE(why, delivered && !test_fragments_pending(f.ws),
        "IPv4 length=65535 proto=%u: TCP bytes=%llu UDP callbacks=%u; pending=%u",
        proto, (unsigned long long)f.state.payload_byte_count,
        malformed_udp_count(&f), !!test_fragments_pending(f.ws));
    return RESULT_PASS;
}

static struct fixture *malformed_fuzz_fixture;
static uint8_t malformed_fuzz_bytes[160];
static unsigned malformed_fuzz_length;
static enum result malformed_fuzz_one(const char **why)
{
    return malformed_observe(malformed_fuzz_fixture, malformed_fuzz_bytes,
        malformed_fuzz_length, true, false, why);
}

static int malformed_state_init(struct fixture *f, unsigned state)
{
    if (!fixture_init(f)) return 0;
    f->state.quiet_payload = 1;
    if (state != II_TCP_STATE_ESTABLISHED) {
        fixture_prepare_sender(f);
        TEST_CONDITION(test_api_close(f->ws, f->conn, &f->state) == 0,
            "Phase 4 state setup: local close failed");
        fixture_run_timers(f);
        free_output(&f->state);
        if (state == II_TCP_STATE_FIN_WAIT2) {
            uint8_t p[64];
            unsigned n = malformed_frame(f, p, 6, 20, 20, 0);
            fixture_deliver(f, malformed_exact_packet(p, n));
            free_output(&f->state);
        }
    }
    TEST_CONDITION(f->conn->state == state,
        "Phase 4 state setup: expected=%u observed=%u", state, f->conn->state);
    test_event_log_clear(&f->state);
    return 1;
}

static enum result malformed_state_control(unsigned state, const char **why)
{
    struct fixture f;
    uint8_t p[64];
    if (!malformed_state_init(&f, state)) return RESULT_ERROR;
    unsigned n = malformed_frame(&f, p, 6, 20, 20, 4);
    fixture_deliver(&f, malformed_exact_packet(p, n));
    TEST_REQUIRE(why, f.state.payload_byte_count == 4,
        "clean state=%u positive control: expected 4 TCP bytes, observed=%llu",
        state, (unsigned long long)f.state.payload_byte_count);
    return RESULT_PASS;
}

static enum result malformed_fuzz(unsigned proto, const char **why)
{
    struct fuzz_config config = fuzz_config_get();
    char prefix[512];
    if (snprintf(prefix, sizeof(prefix), "%s-phase4-%s", config.failure_prefix,
            proto == 6 ? "tcp" : "udp") >= (int)sizeof(prefix)) {
        *why = "Phase 4 failure artifact prefix is too long";
        return RESULT_ERROR;
    }
    config.failure_prefix = prefix;
    uint64_t random = config.seed;
    unsigned failures = 0, inconclusive = 0, errors = 0;
    static const uint8_t states[] = { II_TCP_STATE_ESTABLISHED,
        II_TCP_STATE_FIN_WAIT1, II_TCP_STATE_FIN_WAIT2 };
    static struct fixture fixtures[ARRAY_LENGTH(states)];
    struct malformed_recovery controls[ARRAY_LENGTH(states)];
    for (unsigned i = 0; i < ARRAY_LENGTH(states); i++) {
        if (!malformed_state_init(&fixtures[i], states[i])) return RESULT_ERROR;
        struct fixture clean;
        if (!malformed_state_init(&clean, states[i])) return RESULT_ERROR;
        controls[i] = malformed_probe(&clean);
        free_output(&clean.state);
        free(clean.ws);
    }
    for (unsigned i = 0; i < config.cases; i++) {
        uint64_t seed = fuzz_random(&random), r = seed;
        unsigned state_index = fuzz_random(&r) % ARRAY_LENGTH(states);
        struct fixture *f = &fixtures[state_index];
        malformed_fuzz_fixture = f;
        unsigned thl = proto == 6 ? 20 + 4 * (fuzz_random(&r) % 11) : 8;
        unsigned ihl = 20 + 4 * (fuzz_random(&r) % 11);
        unsigned payload = fuzz_random(&r) % 8;
        uint8_t *p = malformed_fuzz_bytes;
        /* Maximum generated frame: 14 + 60 + 60 + 7 = 141. */
        unsigned n = malformed_frame(f, p, proto, ihl, thl, payload);
        switch (i % 4) {
        case 0: /* Every cut is shorter than the declared IPv4 length. */
            n = fuzz_random(&r) % n; break;
        case 1: /* Inconsistent outer length, plus a randomly damaged L4 field. */
            malformed_u16(p + 16, 65535);
            p[14 + ihl + (proto == 6 ? 12 : 4)] = (uint8_t)fuzz_random(&r);
            malformed_ip_sum(p, ihl); break;
        case 2: /* Length underflow below the physical transport base header. */
            if (proto == 6) {
                p[14 + ihl + 12] = (fuzz_random(&r) % 5) << 4;
                malformed_transport_sum(p, ihl, thl + payload);
            } else {
                malformed_u16(p + 14 + ihl + 4, fuzz_random(&r) % 8);
                p[14 + ihl + 6] = p[14 + ihl + 7] = 0;
            }
            break;
        case 3: /* Nonzero offset whose end cannot fit in an IPv4 datagram. */
            malformed_u16(p + 20, 0x1fff);
            malformed_ip_sum(p, ihl); break;
        }
        malformed_fuzz_length = n;
        fprintf(stderr, "phase4 fuzz: seed=0x%016llx index=%u case_seed=0x%016llx "
            "proto=%u state=%u length=%u\n", (unsigned long long)config.seed,
            i, (unsigned long long)seed, proto, f->conn->state, n);
        const char *detail = NULL;
        enum result result = run_isolated(malformed_fuzz_one, NULL, &detail, 2);
        if (result != RESULT_PASS) {
            void *pkt = malformed_exact_packet(p, n);
            bool saved = fuzz_save_failure(&config, seed, i, pkt, &f->state);
            iip_ops_pkt_free(pkt, &f->state);
            if (saved) {
                char path[512];
                int count = snprintf(path, sizeof(path), "%s-%016llx-%u.txt",
                    config.failure_prefix, (unsigned long long)seed, i);
                FILE *metadata = count >= 0 && count < (int)sizeof(path)
                    ? fopen(path, "a") : NULL;
                if (!metadata) saved = false;
                else {
                    struct malformed_recovery c = controls[state_index];
                    if (fprintf(metadata, "suite_seed=0x%016llx\nproto=%u\n"
                            "tcp_state=%u\nresult=%s\nclean_control=%s\nclean_valid=%u\n"
                            "clean_tcp_bytes=%llu\nclean_tcp_chunks=%u\nclean_seq_delta=%u\n"
                            "clean_state=%u\nclean_udp_count=%u\nclean_udp_len=%u\nclean_udp_first=%u\n",
                            (unsigned long long)config.seed, proto,
                            f->conn->state, detail ? detail : "no diagnostic",
                            malformed_control_id(states[state_index]), malformed_control_ok(c),
                            (unsigned long long)c.bytes, c.chunks, c.seq_delta, c.state,
                            c.udp_count, c.udp_len, c.udp_first) < 0)
                        saved = false;
                    if (fclose(metadata)) saved = false;
                }
            }
            fprintf(stderr, "phase4 fuzz failure: %s; artifact saved=%u\n",
                detail ? detail : "no diagnostic", saved);
            if (result == RESULT_INCONCLUSIVE) inconclusive++;
            else if (result == RESULT_ERROR && !test_process_failed) errors++;
            else failures++;
            if (!saved) { *why = "could not save Phase 4 failure packet"; return RESULT_ERROR; }
        }
    }
    if (errors) {
        *why = "Phase 4 infrastructure error; see per-input diagnostics";
        return RESULT_ERROR;
    }
    TEST_REQUIRE(why, !failures, "Phase 4 proto=%u seed=0x%016llx: %u/%u cases failed; "
        "see per-input diagnostics and saved packets", proto,
        (unsigned long long)config.seed, failures, config.cases);
    if (inconclusive) {
        snprintf(test_failure_detail, sizeof(test_failure_detail),
            "Phase 4 proto=%u: %u/%u inputs inconclusive; recovery equals failing clean controls "
            "MAL-VALID-FIN-WAIT1/MAL-VALID-FIN-WAIT2; see per-input diagnostics",
            proto, inconclusive, config.cases);
        *why = test_failure_detail;
        return RESULT_INCONCLUSIVE;
    }
    return RESULT_PASS;
}

static enum result test_mal_valid_established(const char **why)
{ return malformed_state_control(II_TCP_STATE_ESTABLISHED, why); }

static enum result test_mal_tcp_cut_00(const char **why)
{
    return malformed_truncate(6, 0, false, why);
}

static enum result test_mal_tcp_cut_01(const char **why)
{
    return malformed_truncate(6, 1, false, why);
}

static enum result test_mal_tcp_cut_02(const char **why)
{
    return malformed_truncate(6, 2, false, why);
}

static enum result test_mal_tcp_cut_03(const char **why)
{
    return malformed_truncate(6, 3, false, why);
}

static enum result test_mal_tcp_cut_04(const char **why)
{
    return malformed_truncate(6, 4, false, why);
}

static enum result test_mal_tcp_cut_05(const char **why)
{
    return malformed_truncate(6, 5, false, why);
}

static enum result test_mal_tcp_cut_06(const char **why)
{
    return malformed_truncate(6, 6, false, why);
}

static enum result test_mal_tcp_cut_07(const char **why)
{
    return malformed_truncate(6, 7, false, why);
}

static enum result test_mal_tcp_cut_08(const char **why)
{
    return malformed_truncate(6, 8, false, why);
}

static enum result test_mal_tcp_cut_09(const char **why)
{
    return malformed_truncate(6, 9, false, why);
}

static enum result test_mal_tcp_cut_10(const char **why)
{
    return malformed_truncate(6, 10, false, why);
}

static enum result test_mal_tcp_cut_11(const char **why)
{
    return malformed_truncate(6, 11, false, why);
}

static enum result test_mal_tcp_cut_12(const char **why)
{
    return malformed_truncate(6, 12, false, why);
}

static enum result test_mal_tcp_cut_13(const char **why)
{
    return malformed_truncate(6, 13, false, why);
}

static enum result test_mal_tcp_cut_14(const char **why)
{
    return malformed_truncate(6, 14, false, why);
}

static enum result test_mal_tcp_cut_15(const char **why)
{
    return malformed_truncate(6, 15, false, why);
}

static enum result test_mal_tcp_cut_16(const char **why)
{
    return malformed_truncate(6, 16, false, why);
}

static enum result test_mal_tcp_cut_17(const char **why)
{
    return malformed_truncate(6, 17, false, why);
}

static enum result test_mal_tcp_cut_18(const char **why)
{
    return malformed_truncate(6, 18, false, why);
}

static enum result test_mal_tcp_cut_19(const char **why)
{
    return malformed_truncate(6, 19, false, why);
}

static enum result test_mal_tcp_cut_20(const char **why)
{
    return malformed_truncate(6, 20, false, why);
}

static enum result test_mal_tcp_cut_21(const char **why)
{
    return malformed_truncate(6, 21, false, why);
}

static enum result test_mal_tcp_cut_22(const char **why)
{
    return malformed_truncate(6, 22, false, why);
}

static enum result test_mal_tcp_cut_23(const char **why)
{
    return malformed_truncate(6, 23, false, why);
}

static enum result test_mal_tcp_cut_24(const char **why)
{
    return malformed_truncate(6, 24, false, why);
}

static enum result test_mal_tcp_cut_25(const char **why)
{
    return malformed_truncate(6, 25, false, why);
}

static enum result test_mal_tcp_cut_26(const char **why)
{
    return malformed_truncate(6, 26, false, why);
}

static enum result test_mal_tcp_cut_27(const char **why)
{
    return malformed_truncate(6, 27, false, why);
}

static enum result test_mal_tcp_cut_28(const char **why)
{
    return malformed_truncate(6, 28, false, why);
}

static enum result test_mal_tcp_cut_29(const char **why)
{
    return malformed_truncate(6, 29, false, why);
}

static enum result test_mal_tcp_cut_30(const char **why)
{
    return malformed_truncate(6, 30, false, why);
}

static enum result test_mal_tcp_cut_31(const char **why)
{
    return malformed_truncate(6, 31, false, why);
}

static enum result test_mal_tcp_cut_32(const char **why)
{
    return malformed_truncate(6, 32, false, why);
}

static enum result test_mal_tcp_cut_33(const char **why)
{
    return malformed_truncate(6, 33, false, why);
}

static enum result test_mal_tcp_cut_34(const char **why)
{
    return malformed_truncate(6, 34, false, why);
}

static enum result test_mal_tcp_cut_35(const char **why)
{
    return malformed_truncate(6, 35, false, why);
}

static enum result test_mal_tcp_cut_36(const char **why)
{
    return malformed_truncate(6, 36, false, why);
}

static enum result test_mal_tcp_cut_37(const char **why)
{
    return malformed_truncate(6, 37, false, why);
}

static enum result test_mal_tcp_cut_38(const char **why)
{
    return malformed_truncate(6, 38, false, why);
}

static enum result test_mal_tcp_cut_39(const char **why)
{
    return malformed_truncate(6, 39, false, why);
}

static enum result test_mal_tcp_cut_40(const char **why)
{
    return malformed_truncate(6, 40, false, why);
}

static enum result test_mal_tcp_cut_41(const char **why)
{
    return malformed_truncate(6, 41, false, why);
}

static enum result test_mal_tcp_cut_42(const char **why)
{
    return malformed_truncate(6, 42, false, why);
}

static enum result test_mal_tcp_cut_43(const char **why)
{
    return malformed_truncate(6, 43, false, why);
}

static enum result test_mal_tcp_cut_44(const char **why)
{
    return malformed_truncate(6, 44, false, why);
}

static enum result test_mal_tcp_cut_45(const char **why)
{
    return malformed_truncate(6, 45, false, why);
}

static enum result test_mal_tcp_cut_46(const char **why)
{
    return malformed_truncate(6, 46, false, why);
}

static enum result test_mal_tcp_cut_47(const char **why)
{
    return malformed_truncate(6, 47, false, why);
}

static enum result test_mal_tcp_cut_48(const char **why)
{
    return malformed_truncate(6, 48, false, why);
}

static enum result test_mal_tcp_cut_49(const char **why)
{
    return malformed_truncate(6, 49, false, why);
}

static enum result test_mal_tcp_cut_50(const char **why)
{
    return malformed_truncate(6, 50, false, why);
}

static enum result test_mal_tcp_cut_51(const char **why)
{
    return malformed_truncate(6, 51, false, why);
}

static enum result test_mal_tcp_cut_52(const char **why)
{
    return malformed_truncate(6, 52, false, why);
}

static enum result test_mal_tcp_cut_53(const char **why)
{
    return malformed_truncate(6, 53, false, why);
}

static enum result test_mal_tcp_cut_54(const char **why)
{
    return malformed_truncate(6, 54, false, why);
}

static enum result test_mal_tcp_nested_00(const char **why)
{
    return malformed_truncate(6, 34, true, why);
}

static enum result test_mal_tcp_nested_01(const char **why)
{
    return malformed_truncate(6, 35, true, why);
}

static enum result test_mal_tcp_nested_02(const char **why)
{
    return malformed_truncate(6, 36, true, why);
}

static enum result test_mal_tcp_nested_03(const char **why)
{
    return malformed_truncate(6, 37, true, why);
}

static enum result test_mal_tcp_nested_04(const char **why)
{
    return malformed_truncate(6, 38, true, why);
}

static enum result test_mal_tcp_nested_05(const char **why)
{
    return malformed_truncate(6, 39, true, why);
}

static enum result test_mal_tcp_nested_06(const char **why)
{
    return malformed_truncate(6, 40, true, why);
}

static enum result test_mal_tcp_nested_07(const char **why)
{
    return malformed_truncate(6, 41, true, why);
}

static enum result test_mal_tcp_nested_08(const char **why)
{
    return malformed_truncate(6, 42, true, why);
}

static enum result test_mal_tcp_nested_09(const char **why)
{
    return malformed_truncate(6, 43, true, why);
}

static enum result test_mal_tcp_nested_10(const char **why)
{
    return malformed_truncate(6, 44, true, why);
}

static enum result test_mal_tcp_nested_11(const char **why)
{
    return malformed_truncate(6, 45, true, why);
}

static enum result test_mal_tcp_nested_12(const char **why)
{
    return malformed_truncate(6, 46, true, why);
}

static enum result test_mal_tcp_nested_13(const char **why)
{
    return malformed_truncate(6, 47, true, why);
}

static enum result test_mal_tcp_nested_14(const char **why)
{
    return malformed_truncate(6, 48, true, why);
}

static enum result test_mal_tcp_nested_15(const char **why)
{
    return malformed_truncate(6, 49, true, why);
}

static enum result test_mal_tcp_nested_16(const char **why)
{
    return malformed_truncate(6, 50, true, why);
}

static enum result test_mal_tcp_nested_17(const char **why)
{
    return malformed_truncate(6, 51, true, why);
}

static enum result test_mal_tcp_nested_18(const char **why)
{
    return malformed_truncate(6, 52, true, why);
}

static enum result test_mal_tcp_nested_19(const char **why)
{
    return malformed_truncate(6, 53, true, why);
}

static enum result test_mal_udp_nested_00(const char **why)
{
    return malformed_truncate(17, 34, true, why);
}

static enum result test_mal_udp_nested_01(const char **why)
{
    return malformed_truncate(17, 35, true, why);
}

static enum result test_mal_udp_nested_02(const char **why)
{
    return malformed_truncate(17, 36, true, why);
}

static enum result test_mal_udp_nested_03(const char **why)
{
    return malformed_truncate(17, 37, true, why);
}

static enum result test_mal_udp_nested_04(const char **why)
{
    return malformed_truncate(17, 38, true, why);
}

static enum result test_mal_udp_nested_05(const char **why)
{
    return malformed_truncate(17, 39, true, why);
}

static enum result test_mal_udp_nested_06(const char **why)
{
    return malformed_truncate(17, 40, true, why);
}

static enum result test_mal_udp_nested_07(const char **why)
{
    return malformed_truncate(17, 41, true, why);
}

static enum result test_mal_ip_total_0(const char **why)
{
    return malformed_field_case(MAL_IP_TOTAL, 0, why);
}

static enum result test_mal_ip_total_1(const char **why)
{
    return malformed_field_case(MAL_IP_TOTAL, 1, why);
}

static enum result test_mal_ip_total_19(const char **why)
{
    return malformed_field_case(MAL_IP_TOTAL, 19, why);
}

static enum result test_mal_ip_total_65535(const char **why)
{
    return malformed_field_case(MAL_IP_TOTAL, 65535, why);
}

static enum result test_mal_ip_ihl_0(const char **why)
{
    return malformed_field_case(MAL_IP_IHL, 0, why);
}

static enum result test_mal_ip_ihl_4(const char **why)
{
    return malformed_field_case(MAL_IP_IHL, 4, why);
}

static enum result test_mal_ip_ihl_15(const char **why)
{
    return malformed_field_case(MAL_IP_IHL, 15, why);
}

static enum result test_mal_tcp_offset_0(const char **why)
{
    return malformed_field_case(MAL_TCP_OFFSET, 0, why);
}

static enum result test_mal_tcp_offset_4(const char **why)
{
    return malformed_field_case(MAL_TCP_OFFSET, 4, why);
}

static enum result test_mal_tcp_offset_8(const char **why)
{
    return malformed_field_case(MAL_TCP_OFFSET, 8, why);
}

static enum result test_mal_tcp_offset_15(const char **why)
{
    return malformed_field_case(MAL_TCP_OFFSET, 15, why);
}

static enum result test_mal_udp_length_0(const char **why)
{
    return malformed_field_case(MAL_UDP_LENGTH, 0, why);
}

static enum result test_mal_udp_length_1(const char **why)
{
    return malformed_field_case(MAL_UDP_LENGTH, 1, why);
}

static enum result test_mal_udp_length_7(const char **why)
{
    return malformed_field_case(MAL_UDP_LENGTH, 7, why);
}

static enum result test_mal_udp_length_17(const char **why)
{
    return malformed_field_case(MAL_UDP_LENGTH, 17, why);
}

static enum result test_mal_udp_length_65535(const char **why)
{
    return malformed_field_case(MAL_UDP_LENGTH, 65535, why);
}

static enum result test_mal_fragment_8192(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 8192, why);
}

static enum result test_mal_fragment_8189(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 8189, why);
}

static enum result test_mal_fragment_8190(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 8190, why);
}

static enum result test_mal_fragment_8191(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 8191, why);
}

static enum result test_mal_fragment_16383(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 16383, why);
}

static enum result test_mal_ip_corrupt(const char **why)
{
    return malformed_field_case(MAL_IP_CHECKSUM, 0, why);
}

static enum result test_mal_tcp_corrupt(const char **why)
{
    return malformed_field_case(MAL_TCP_CHECKSUM, 0, why);
}

static enum result test_mal_udp_corrupt(const char **why)
{
    return malformed_field_case(MAL_UDP_CHECKSUM, 0, why);
}

static enum result test_mal_combined_corrupt(const char **why)
{
    return malformed_field_case(MAL_COMBINED, 0, why);
}

static enum result test_mal_tcp_option_zero(const char **why)
{
    return malformed_option_case(0, why);
}

static enum result test_mal_tcp_option_one(const char **why)
{
    return malformed_option_case(1, why);
}

static enum result test_mal_tcp_option_overrun(const char **why)
{
    return malformed_option_case(2, why);
}

static enum result test_mal_tcp_option_255(const char **why)
{
    return malformed_option_case(3, why);
}

static enum result test_mal_tcp_option_lone_kind(const char **why)
{
    return malformed_option_case(4, why);
}

static enum result test_mal_tcp_option_bad_tail(const char **why)
{
    return malformed_option_case(5, why);
}

static enum result test_mal_tcp_option_mss(const char **why)
{
    return malformed_option_case(6, why);
}

static enum result test_mal_tcp_option_ws(const char **why)
{
    return malformed_option_case(7, why);
}

static enum result test_mal_tcp_option_ts(const char **why)
{
    return malformed_option_case(8, why);
}

static enum result test_mal_tcp_option_sack(const char **why)
{
    return malformed_option_case(9, why);
}

static enum result test_mal_tcp_option_sack_permitted(const char **why)
{
    return malformed_option_case(10, why);
}

static enum result test_mal_valid_tcp_min(const char **why)
{
    return malformed_valid_case(0, why);
}

static enum result test_mal_valid_headers_max(const char **why)
{
    return malformed_valid_case(1, why);
}

static enum result test_mal_valid_udp_min(const char **why)
{
    return malformed_valid_case(2, why);
}

static enum result test_mal_valid_udp_no_checksum(const char **why)
{
    return malformed_valid_case(3, why);
}

static enum result test_mal_max_ip_tcp(const char **why)
{
    return malformed_maximum(6, why);
}

static enum result test_mal_fuzz_tcp(const char **why)
{
    return malformed_fuzz(6, why);
}

static enum result test_mal_max_ip_udp(const char **why)
{
    return malformed_maximum(17, why);
}

static enum result test_mal_fuzz_udp(const char **why)
{
    return malformed_fuzz(17, why);
}

static enum result test_mal_fragment_8185(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 8185, why);
}

static enum result test_mal_fragment_8186(const char **why)
{
    return malformed_field_case(MAL_FRAGMENT, 8186, why);
}

static enum result test_mal_valid_fin_wait1(const char **why)
{
    return malformed_state_control(II_TCP_STATE_FIN_WAIT1, why);
}

static enum result test_mal_valid_fin_wait2(const char **why)
{
    return malformed_state_control(II_TCP_STATE_FIN_WAIT2, why);
}

static enum result test_mal_udp_empty_length_0(const char **why)
{
    return malformed_field_case(MAL_UDP_EMPTY_LENGTH, 0, why);
}

static enum result test_mal_udp_empty_length_1(const char **why)
{
    return malformed_field_case(MAL_UDP_EMPTY_LENGTH, 1, why);
}

static enum result test_mal_udp_empty_length_7(const char **why)
{
    return malformed_field_case(MAL_UDP_EMPTY_LENGTH, 7, why);
}

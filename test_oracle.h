/* Phase 8: native API + byte-oriented peer. Never read a connection's
 * sequence, state, queue, or timer to construct an input or expected result.
 * Pool initialization and now_ms are required integration inputs. The shared
 * callback binding extracts the delivered slice from iip's descriptor ABI. */
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/utsname.h>

struct oracle_peer {
    struct test_state state;
    struct iip_workspace *ws;
    uint32_t tx, rx;
};
struct oracle_segment {
    uint32_t seq, ack;
    unsigned flags, length;
    const uint8_t *data;
};
struct oracle_transcript {
    uint8_t received[16], sent[16];
    unsigned eof;
};

static uint16_t oracle_u16(const uint8_t *p)
{ return (uint16_t)((unsigned)p[0] * 256 + p[1]); }
static uint32_t oracle_u32(const uint8_t *p)
{ return (uint32_t)oracle_u16(p) * 65536U + oracle_u16(p + 2); }
static void oracle_put32(uint8_t *p, uint32_t n)
{ malformed_u16(p, n >> 16); malformed_u16(p + 2, n); }

static int oracle_parse(void *packet, struct oracle_segment *s)
{
    const uint8_t *p = iip_ops_pkt_get_data(packet, NULL);
    unsigned size = iip_ops_pkt_get_len(packet, NULL);
    TEST_CONDITION(size >= 54 && oracle_u16(p + 12) == 0x0800,
        "oracle output: expected Ethernet/IPv4/TCP, bytes=%u", size);
    const uint8_t *ip = p + 14;
    unsigned ihl = (ip[0] & 15) * 4, total = oracle_u16(ip + 2);
    TEST_CONDITION(ip[0] >> 4 == 4 && ihl >= 20 && total >= ihl + 20 &&
        total <= size - 14 && ip[9] == 6 && !(oracle_u16(ip + 6) & 0x3fff),
        "oracle output: invalid IPv4 lengths/protocol/fragment");
    TEST_CONDITION(oracle_u32(ip + 12) == 0xc0000201U &&
        oracle_u32(ip + 16) == 0xc6336402U && !malformed_sum(ip, ihl, 0),
        "oracle output: address or IPv4 checksum mismatch");
    const uint8_t *tcp = ip + ihl;
    unsigned thl = (tcp[12] >> 4) * 4, n = total - ihl;
    uint32_t pseudo = (uint16_t)~malformed_sum(ip + 12, 8, 0);
    TEST_CONDITION(thl >= 20 && thl <= n && oracle_u16(tcp) == 15000 &&
        oracle_u16(tcp + 2) == 25000 && !malformed_sum(tcp, n, pseudo + 6 + n),
        "oracle output: TCP length/port/checksum mismatch");
    s->seq = oracle_u32(tcp + 4); s->ack = oracle_u32(tcp + 8);
    s->flags = tcp[13]; s->length = n - thl; s->data = tcp + thl;
    return 1;
}

static int oracle_run(struct oracle_peer *p, void *packet)
{
    uint32_t next = 0;
    test_current_opaque = &p->state;
    p->ws->now_ms = (uint32_t)(p->state.now_ns / 1000000);
    TEST_CONDITION(iip_run(p->ws, packet ? &packet : NULL, packet ? 1 : 0,
        &next, &p->state) == 0, "oracle native RUN failed");
    return 1;
}

static void *oracle_packet(struct oracle_peer *p, uint32_t seq, unsigned flags,
        const uint8_t *data, unsigned n, int bad_checksum)
{
    uint8_t b[128] = {0};
    assert(n <= sizeof(b) - 54);
    b[0] = 2; b[6] = 4; malformed_u16(b + 12, 0x0800);
    b[14] = 0x45; b[22] = 64; b[23] = 6;
    malformed_u16(b + 16, 40 + n);
    oracle_put32(b + 26, 0xc6336402U); oracle_put32(b + 30, 0xc0000201U);
    malformed_u16(b + 34, 25000); malformed_u16(b + 36, 15000);
    oracle_put32(b + 38, seq); oracle_put32(b + 42, p->tx);
    b[46] = 0x50; b[47] = flags; malformed_u16(b + 48, 65535);
    if (n) memcpy(b + 54, data, n);
    malformed_transport_sum(b, 20, 20 + n); malformed_ip_sum(b, 20);
    if (bad_checksum) b[50] ^= 1;
    return malformed_exact_packet(b, 54 + n);
}

static int oracle_input(struct oracle_peer *p, uint32_t seq, unsigned flags,
        const uint8_t *data, unsigned n, int bad_checksum)
{ return oracle_run(p, oracle_packet(p, seq, flags, data, n, bad_checksum)); }

static int oracle_control(struct oracle_peer *p, unsigned flags)
{
    int found = 0;
    for (unsigned i = 0; i < p->state.out_cnt; i++) {
        struct oracle_segment s;
        if (!oracle_parse(p->state.out[i], &s)) return 0;
        TEST_CONDITION(!(s.flags & 4) && !s.length, "oracle unexpected RST or unsent payload");
        if ((s.flags & 0x17) == flags && !s.length && s.seq == p->tx &&
            (!(flags & 16) || s.ack == p->rx)) found = 1;
    }
    TEST_CONDITION(found, "oracle missing control flags=%02x seq=%u ack=%u outputs=%u",
        flags, p->tx, p->rx, p->state.out_cnt);
    free_output(&p->state);
    return 1;
}

static int oracle_open(struct oracle_peer *p)
{
    memset(p, 0, sizeof(*p));
    p->ws = calloc(1, sizeof(*p->ws));
    if (!p->ws) return fixture_setup_failed("oracle workspace allocation failed");
    test_workspace_init(p->ws);
    p->state.local_mac[0] = 2;
    p->state.local_ip4_be = htonl(0xc0000201U);
    p->state.use_fake_clock = p->state.quiet_payload = 1;
    p->state.accept_arbitrary_payload = p->state.oracle.enabled = 1;
    p->state.now_ns = UINT64_C(1000000000);
    TEST_CONDITION(oracle_run(p, NULL), "oracle initial clock failed");
    uint8_t peer_mac[6] = {4};
    TEST_CONDITION(iip_tcp_ipv4_ethernet_connect(p->ws, p->state.local_mac,
        p->state.local_ip4_be, htons(15000), peer_mac, htonl(0xc6336402U),
        htons(25000), NULL, 0, NULL, 0, &p->state) == 0, "oracle native OPEN failed");
    TEST_CONDITION(oracle_run(p, NULL), "oracle SYN run failed");
    TEST_CONDITION(p->state.out_cnt == 1, "oracle expected one SYN, actual=%u", p->state.out_cnt);
    struct oracle_segment syn;
    if (!oracle_parse(p->state.out[0], &syn)) return 0;
    TEST_CONDITION((syn.flags & 0x17) == 2 && !syn.length, "oracle invalid initial SYN");
    p->tx = syn.seq + 1; p->rx = UINT32_MAX - 7U;
    free_output(&p->state);
    TEST_CONDITION(oracle_input(p, p->rx, 0x12, NULL, 0, 0), "oracle SYN+ACK failed");
    p->rx++;
    TEST_CONDITION(p->state.oracle.connected == 1, "oracle expected native CONNECTED once, actual=%u",
        p->state.oracle.connected);
    return oracle_control(p, 0x10);
}

static int oracle_received(struct oracle_peer *p, const uint8_t *expected, size_t n)
{
    TEST_CONDITION(!p->state.oracle.overflow && p->state.oracle.length == n &&
        !memcmp(p->state.oracle.bytes, expected, n),
        "oracle delivered stream: expected=%zu bytes, actual=%zu overflow=%u (content compared)",
        n, p->state.oracle.length, p->state.oracle.overflow);
    return 1;
}

static int oracle_reset(struct oracle_peer *p)
{
    free_output(&p->state);
    TEST_CONDITION(oracle_input(p, p->rx, 0x14, NULL, 0, 0), "oracle reset input failed");
    TEST_CONDITION(p->state.oracle.closed == 1, "oracle expected native CLOSED once, actual=%u",
        p->state.oracle.closed);
    free_output(&p->state); free(p->ws);
    return 1;
}

static enum result test_oracle_receive(const char **why, int mode)
{
    struct oracle_peer p;
    uint8_t bytes[17];
    for (unsigned i = 0; i < sizeof(bytes); i++) bytes[i] = i;
    TEST_REQUIRE(why, oracle_open(&p), "native handshake failed; see diagnostics");
    if (mode == 1) {
        TEST_REQUIRE(why, oracle_input(&p, p.rx + 8, 0x10, bytes + 8, 8, 0) &&
            oracle_received(&p, bytes, 0), "out-of-order bytes delivered before gap fill");
    } else if (mode == 2) {
        TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, bytes, 16, 1) &&
            oracle_received(&p, bytes, 0), "bad TCP checksum delivered application bytes");
    }
    TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, bytes, mode == 1 ? 8 : 16, 0) &&
        oracle_received(&p, bytes, 16), "valid receive/gap recovery stream mismatch");
    if (mode == 1)
        TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, bytes, 16, 0) &&
            oracle_received(&p, bytes, 16), "duplicate segment delivered twice");
    p.rx += 16;
    TEST_REQUIRE(why, oracle_input(&p, p.rx, 0x10, bytes + 16, 1, 0) &&
        oracle_received(&p, bytes, 17), "fresh data after boundary input not delivered");
    p.rx++;
    /* Bounded profile; allow delayed ACKs, without reading their timers. */
    p.state.now_ns += UINT64_C(200000000);
    TEST_REQUIRE(why, oracle_run(&p, NULL) && oracle_control(&p, 0x10),
        "cumulative wire ACK did not cover the independently tracked stream");
    TEST_REQUIRE(why, oracle_reset(&p), "native cleanup notification missing");
    return RESULT_PASS;
}
static enum result test_oracle_stream(const char **why)
{ return test_oracle_receive(why, 0); }
static enum result test_oracle_duplicate(const char **why)
{ return test_oracle_receive(why, 1); }
static enum result test_oracle_checksum(const char **why)
{ return test_oracle_receive(why, 2); }

static int oracle_half_close(struct oracle_transcript *t)
{
    struct oracle_peer p;
    uint8_t bytes[16];
    for (unsigned i = 0; i < sizeof(bytes); i++) bytes[i] = i;
    if (!oracle_open(&p)) return 0;
    /* Peer writes 3 + 13 bytes, then closes only its sending direction. */
    TEST_CONDITION(oracle_input(&p, p.rx, 0x10, bytes, 3, 0), "first write failed");
    p.rx += 3;
    TEST_CONDITION(oracle_input(&p, p.rx, 0x10, bytes + 3, 13, 0), "second write failed");
    p.rx += 13;
    TEST_CONDITION(oracle_input(&p, p.rx, 0x11, NULL, 0, 0), "peer FIN failed");
    p.rx++;
    TEST_CONDITION(oracle_received(&p, bytes, 16) && p.state.oracle.eof == 1,
        "half-close: data/EOF mismatch");
    memcpy(t->received, p.state.oracle.bytes, 16); t->eof = p.state.oracle.eof;
    free_output(&p.state);
    void *packet = iip_ops_pkt_alloc(&p.state);
    uint8_t *data = iip_ops_pkt_get_data(packet, &p.state);
    for (unsigned i = 0; i < 16; i++) data[i] = 0xa0 + i;
    iip_ops_pkt_set_len(packet, 16, &p.state);
    TEST_CONDITION(iip_tcp_send(p.ws, p.state.oracle.conn_id, &packet, 1, &p.state) == 0 &&
        oracle_run(&p, NULL), "half-close: SEND after peer FIN failed");
    uint8_t seen[16] = {0};
    for (unsigned i = 0; i < p.state.out_cnt; i++) {
        struct oracle_segment s;
        if (!oracle_parse(p.state.out[i], &s)) return 0;
        unsigned off = s.seq - p.tx;
        TEST_CONDITION(!(s.flags & 7) && (s.flags & 16) && s.ack == p.rx,
            "half-close: unexpected control/ACK after SEND");
        if (!s.length) continue;
        TEST_CONDITION(off <= 16 && s.length <= 16 - off, "half-close: output beyond sent stream");
        for (unsigned j = 0; j < s.length; j++) {
            TEST_CONDITION(s.data[j] == 0xa0 + off + j, "half-close: output data corrupt at %u", off+j);
            seen[off+j] = 1; t->sent[off+j] = s.data[j];
        }
    }
    for (unsigned i = 0; i < 16; i++)
        TEST_CONDITION(seen[i], "half-close: missing output byte %u", i);
    p.tx += 16; free_output(&p.state);
    TEST_CONDITION(oracle_input(&p, p.rx, 0x10, NULL, 0, 0), "half-close: data ACK failed");
    TEST_CONDITION(iip_tcp_close(p.ws, p.state.oracle.conn_id, &p.state) == 0 &&
        oracle_run(&p, NULL) && oracle_control(&p, 0x11), "half-close: local FIN missing");
    p.tx++;
    TEST_CONDITION(oracle_input(&p, p.rx, 0x10, NULL, 0, 0) && p.state.oracle.closed == 1,
        "half-close: completion callback missing");
    TEST_CONDITION(oracle_received(&p, bytes, 16) && p.state.oracle.eof == 1,
        "half-close: application transcript changed during completion");
    free_output(&p.state); free(p.ws);
    return 1;
}

/* Linux loopback is a second execution of the APPLICATION trace, not a
 * packet-level peer or timing oracle. No privileged sockets or sleeps. */
static int oracle_socket_timeout(int fd)
{
    struct timeval tv = {2, 0};
    return !setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) &&
        !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
static int oracle_socket_bytes(int fd, uint8_t *bytes, size_t length, int writing)
{
    size_t off = 0;
    while (off < length) {
        ssize_t n = writing ? send(fd, bytes + off, length - off, MSG_NOSIGNAL) :
            recv(fd, bytes + off, length - off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}
static enum result test_oracle_linux(const char **why)
{
    struct oracle_transcript native = {0}, linux_result = {0};
    /* A missing reference cannot hide a native failure. */
    TEST_REQUIRE(why, oracle_half_close(&native), "native application trace failed; see diagnostics");
#ifndef __linux__
    *why = "Linux TCP reference unavailable on this host";
    return RESULT_INCONCLUSIVE;
#else
    int listener = -1, client = -1, server = -1;
    enum result result = RESULT_INCONCLUSIVE;
    const char *step = "socket";
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t alen = sizeof(address);
    listener = socket(AF_INET, SOCK_STREAM, 0); client = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || client < 0) goto done;
    step = "timeout/bind/listen";
    if (!oracle_socket_timeout(listener) || !oracle_socket_timeout(client) ||
        bind(listener, (struct sockaddr *)&address, alen) || listen(listener, 1) ||
        getsockname(listener, (struct sockaddr *)&address, &alen)) goto done;
    step = "connect/accept";
    if (connect(client, (struct sockaddr *)&address, alen)) goto done;
    server = accept(listener, NULL, NULL);
    if (server < 0 || !oracle_socket_timeout(server)) goto done;
    uint8_t tx[16], rx[16], extra;
    for (unsigned i = 0; i < 16; i++) tx[i] = i;
    step = "request/EOF";
    if (!oracle_socket_bytes(client, tx, 3, 1) || !oracle_socket_bytes(client, tx + 3, 13, 1) ||
        shutdown(client, SHUT_WR) || !oracle_socket_bytes(server, linux_result.received, 16, 0)) goto done;
    ssize_t n = recv(server, &extra, 1, 0);
    if (n < 0) goto done;
    linux_result.eof = n == 0;
    for (unsigned i = 0; i < 16; i++) rx[i] = 0xa0 + i;
    step = "response/EOF";
    if (!oracle_socket_bytes(server, rx, 16, 1) || shutdown(server, SHUT_WR) ||
        !oracle_socket_bytes(client, linux_result.sent, 16, 0)) goto done;
    n = recv(client, &extra, 1, 0);
    if (n < 0) goto done;
    /* Compare each implementation with the independent expected trace too. */
    result = RESULT_FAIL;
    *why = "Linux/native application transcript differs from expected bytes or EOF";
    if (n || !linux_result.eof || memcmp(linux_result.received, tx, 16) ||
        memcmp(linux_result.sent, rx, 16) || native.eof != linux_result.eof ||
        memcmp(native.received, linux_result.received, 16) ||
        memcmp(native.sent, linux_result.sent, 16)) goto done;
    struct utsname host;
    if (!uname(&host)) fprintf(stderr, "Linux reference: %s %s %s\n", host.sysname, host.release, host.machine);
    fprintf(stderr, "Differential transcript: request=000102030405060708090a0b0c0d0e0f EOF=1 response=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf EOF=1\n");
    result = RESULT_PASS;
    *why = NULL;
done:
    if (result == RESULT_INCONCLUSIVE) {
        snprintf(test_failure_detail, sizeof(test_failure_detail), "Linux reference unavailable/incomplete at %s: errno=%d (%s)", step, errno, strerror(errno));
        *why = test_failure_detail;
    }
    if (server >= 0) close(server);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    return result;
#endif
}

/* TCP option layout validation and wire-output scenarios.
 * Included by test_tcp.h after the common fixture and wire helpers.
 */

/* EOL and NOP are one octet. All other options must contain a length
 * field and fit entirely inside the advertised option area. Never advance
 * using an unvalidated length, including when only padding is under test.
 */
static int tcp_options_valid(const uint8_t *options, uint16_t length,
        bool check_padding)
{
    uint16_t at = 0;
    while (at < length) {
        unsigned kind = options[at];
        if (kind == 0) break;
        if (kind == 1) { at++; continue; }
        TEST_CONDITION(length - at >= 2,
            "TCP option offset=%u kind=%u: expected header bytes>=2, actual=%u",
            (unsigned)at, kind, (unsigned)(length - at));
        unsigned size = options[at + 1];
        TEST_CONDITION(size >= 2 && size <= (unsigned)(length - at),
            "TCP option offset=%u kind=%u: expected length=2..%u, actual=%u",
            (unsigned)at, kind, (unsigned)(length - at), size);
        at += size;
    }
    if (check_padding) {
        for (; at < length; at++)
            TEST_CONDITION(options[at] == 0,
                "TCP padding offset=%u: expected=0, actual=%u",
                (unsigned)at, (unsigned)options[at]);
    }
    return 1;
}

static enum result tcp_output_options_case(bool check_padding, const char **why)
{
    struct fixture f;
    void *pkt;
    int valid;
    TEST_REQUIRE(why, fixture_init(&f), "TCP options: fixture initialization failed");
    pkt = fixture_packet(&f, 1, 0, 0);
    TEST_REQUIRE(why, pkt, "TCP options: SYN packet unavailable");
    valid = tcp_options_valid(PB_TCP_OPT(pkt), PB_TCP_OPTLEN(pkt), check_padding);
    iip_ops_pkt_free(pkt, &f.state);
    if (!valid) {
        *why = test_failure_detail;
        return RESULT_FAIL;
    }
    return RESULT_PASS;
}

static enum result test_option_lengths(const char **why)
{
    return tcp_output_options_case(false, why);
}

static enum result test_zero_padding(const char **why)
{
    return tcp_output_options_case(true, why);
}

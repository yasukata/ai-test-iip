/* Inject infrastructure faults without modifying any target-stack behavior. */
#define main harness_program_main
#include "../main.c"
#undef main

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/asan_interface.h>
#endif

static enum result overflow_case(const char **why)
{
    (void)why;
    struct test_state state = { 0 };
    for (unsigned i = 0; i <= ARRAY_LENGTH(state.events); i++)
        test_event_append(&state, TEST_EVENT_CALLBACK, 0, NULL, 0, 0, 0, 0);
    return RESULT_PASS;
}

static int self_test_marker;

static void passing_self_test(void)
{
    self_test_marker = 1;
}

static void overflow_self_test(void)
{
    const char *why = NULL;
    (void)overflow_case(&why);
}

static void exiting_self_test(void) { _exit(7); }
static void missing_report_self_test(void) { _exit(0); }
static void signaled_self_test(void) { raise(SIGKILL); }
static void hanging_self_test(void) { for (;;) pause(); }
static void ignored_alarm_self_test(void)
{
    signal(SIGALRM, SIG_IGN);
    for (;;) pause();
}

static void descendant_self_test(void)
{
    pid_t child = fork();
    assert(child >= 0);
    if (!child) { signal(SIGALRM, SIG_IGN); for (;;) pause(); }
}
static void descendant_timeout_self_test(void)
{
    descendant_self_test();
    ignored_alarm_self_test();
}
static void descendant_missing_self_test(void)
{
    descendant_self_test();
    _exit(0);
}
static void descendant_cleanup_checks(void)
{
    void (*cases[])(void) = { descendant_self_test, descendant_timeout_self_test,
                             descendant_missing_self_test };
    for (unsigned i = 0; i < ARRAY_LENGTH(cases); i++) {
        int channel[2];
        assert(pipe(channel) == 0);
        assert(fcntl(channel[0], F_SETFL, O_NONBLOCK) == 0);
        const char *why = NULL;
        enum result result = run_isolated_self_test(cases[i], &why, 1);
        assert(result == (i == 0 ? RESULT_PASS : i == 1 ? RESULT_FAIL : RESULT_ERROR));
        close(channel[1]);
        char byte;
        ssize_t n = -1;
        for (unsigned attempt = 0; attempt < 1000; attempt++) {
            n = read(channel[0], &byte, 1);
            if (n == 0) break; /* Every inherited writer was closed. */
            assert(n < 0 && (errno == EAGAIN || errno == EINTR));
            const struct timespec delay = { 0, 1000000L };
            nanosleep(&delay, NULL);
        }
        assert(n == 0);
        close(channel[0]);
    }
}

static void isolated_self_test_checks(void)
{
    static const struct {
        void (*run)(void);
        enum result expected;
        const char *reason;
        int process_failed;
    } cases[] = {
        { passing_self_test, RESULT_PASS, NULL, 0 },
        { overflow_self_test, RESULT_ERROR, "overflow", 0 },
        { exiting_self_test, RESULT_ERROR, "exit=7", 1 },
        { missing_report_self_test, RESULT_ERROR, "exit=0", 1 },
        { signaled_self_test, RESULT_FAIL, "signal=", 1 },
        { hanging_self_test, RESULT_FAIL, "timed out after 1 second", 1 },
        { ignored_alarm_self_test, RESULT_FAIL, "timed out after 1 second", 1 },
    };
    for (unsigned i = 0; i < ARRAY_LENGTH(cases); i++) {
        const char *why = NULL;
        assert(run_isolated_self_test(cases[i].run, &why, 1) == cases[i].expected);
        assert(test_process_failed == cases[i].process_failed);
        if (cases[i].reason) assert(why && strstr(why, cases[i].reason));
        else assert(!why);
        /* Each failure must leave the parent ready for another isolated case. */
        assert(run_isolated_self_test(passing_self_test, &why, 1) == RESULT_PASS);
        assert(!why && !test_process_failed && self_test_marker == 0);
    }
}

/* Allocate exactly the declared length so sanitizer runs can detect even a
 * one-octet overread by the option validator. Cases run under the normal
 * isolation timeout so a zero-length option cannot hang the harness check.
 */
static enum result option_validation_case(const char **why)
{
    static const struct {
        const char *name;
        uint8_t bytes[8];
        uint16_t length;
        bool layout, padding;
    } cases[] = {
        { "empty", { 0 }, 0, true, true },
        { "nop", { 1 }, 1, true, true },
        { "eol", { 0 }, 1, true, true },
        { "mss with zero data", { 2, 4, 0, 0 }, 4, true, true },
        { "unknown option", { 99, 2 }, 2, true, true },
        { "nop then mss", { 1, 2, 4, 0, 0 }, 5, true, true },
        { "zero padding", { 2, 4, 0, 0, 0, 0 }, 6, true, true },
        { "nonzero padding", { 0, 1 }, 2, true, false },
        { "zero length", { 2, 0 }, 2, false, false },
        { "length one", { 2, 1 }, 2, false, false },
        { "missing length", { 2 }, 1, false, false },
        { "overrun", { 2, 5, 0, 0 }, 4, false, false },
        { "trailing kind", { 1, 2 }, 2, false, false },
        { "max length", { 99, 255 }, 2, false, false },
    };
    for (unsigned i = 0; i < ARRAY_LENGTH(cases); i++) {
        uint8_t *bytes = cases[i].length ? malloc(cases[i].length) : NULL;
        TEST_REQUIRE(why, !cases[i].length || bytes,
            "%s: allocation failed", cases[i].name);
        if (bytes) memcpy(bytes, cases[i].bytes, cases[i].length);
        int layout = tcp_options_valid(bytes, cases[i].length, false);
        int padding = tcp_options_valid(bytes, cases[i].length, true);
        free(bytes);
        TEST_REQUIRE(why, layout == cases[i].layout,
            "%s: expected layout=%d, actual=%d", cases[i].name,
            cases[i].layout, layout);
        TEST_REQUIRE(why, padding == cases[i].padding,
            "%s: expected padding=%d, actual=%d", cases[i].name,
            cases[i].padding, padding);
    }
    return RESULT_PASS;
}

int main(void)
{
    const char *why = NULL;
    /* Exact-size packets retain their bytes and real capacity when the
     * original reference is released before its clone. Include empty input. */
    for (unsigned n = 0; n <= 55; n++) {
        uint8_t bytes[55];
        memset(bytes, 0xa5, sizeof(bytes));
        void *packet = malformed_exact_packet(bytes, n);
        void *clone = iip_ops_pkt_clone(packet, NULL);
        iip_ops_pkt_free(packet, NULL);
        assert(test_pkt_get_capacity(clone, NULL) == n);
        assert(iip_ops_pkt_get_len(clone, NULL) == n);
        assert(!memcmp(iip_ops_pkt_get_data(clone, NULL), bytes, n));
#if defined(__SANITIZE_ADDRESS__)
        /* Verify that one byte past the declared receive length really is
         * inaccessible to ASan, even for zero-byte and cloned packets. */
        assert(__asan_address_is_poisoned(
            (uint8_t *)iip_ops_pkt_get_data(clone, NULL) + n));
        if (n) assert(!__asan_address_is_poisoned(
            (uint8_t *)iip_ops_pkt_get_data(clone, NULL) + n - 1));
#endif
        iip_ops_pkt_free(clone, NULL);
    }
    assert(run_isolated_test(overflow_case, &why) == RESULT_ERROR);
    assert(why && strstr(why, "overflow"));
    fputs("Option validator negative controls: expected diagnostics follow\n", stderr);
    assert(run_isolated_test(option_validation_case, &why) == RESULT_PASS);
    isolated_self_test_checks();
    descendant_cleanup_checks();
    puts("Runner fault and option validation checks: PASS");
    return 0;
}

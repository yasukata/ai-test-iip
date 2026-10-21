/* TAP and JSON serialization, included after struct test_case is defined. */
static void json_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

static const char *result_name(enum result r)
{
    switch (r) {
    case RESULT_PASS: return "PASS";
    case RESULT_FAIL: return "FAIL";
    case RESULT_SKIP: return "NOT_APPLICABLE";
    case RESULT_TODO: return "DEVIATION";
    case RESULT_INCONCLUSIVE: return "INCONCLUSIVE";
    default: return "ERROR";
    }
}

/* Escape free text so each observation occupies exactly one TAP line and
 * cannot introduce a SKIP/TODO directive or a status marker. JSON retains
 * the original text.
 */
static void tap_text(const char *text)
{
    const unsigned char *start = (const unsigned char *)(text ? text : "");
    for (const unsigned char *p = start; *p; p++) {
        switch (*p) {
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        default:
            if (*p < 32 || *p == 127 || *p == '#' ||
                    (*p == '[' && p - start >= 3 && !memcmp(p - 3, " - ", 3)))
                printf("\\x%02x", *p);
            else putchar(*p);
        }
    }
}

static void report_tap_case(const struct test_case *c, enum result result,
        const char *why, size_t number)
{
    printf("%s %zu - ", (result == RESULT_PASS || result == RESULT_SKIP) ? "ok" : "not ok", number);
    tap_text(c->id);
    putchar(' ');
    tap_text(c->description);
    if (result == RESULT_SKIP) {
        fputs(" # SKIP ", stdout);
        tap_text(why);
    } else if (result == RESULT_TODO) {
        fputs(" # TODO recommendation deviation: ", stdout);
        tap_text(why ? why : "see diagnostics");
    } else if (result != RESULT_PASS) {
        printf(" - [%s] ", result_name(result));
        tap_text(why ? why : "assertion or predicate failed; see diagnostics");
    }
    putchar('\n');
    fflush(stdout);
}

static const char *test_execution_name(void)
{
    switch (test_execution) {
    case TEST_EXEC_NORMAL: return "normal";
    case TEST_EXEC_TIMEOUT: return "timeout";
    case TEST_EXEC_SIGNAL: return "signal";
    case TEST_EXEC_EXIT_ERROR: return "exit-error";
    case TEST_EXEC_MISSING_REPORT: return "missing-report";
    case TEST_EXEC_NOT_RUN: return "not-run";
    default: return "infrastructure-error";
    }
}

static void report_json_case(FILE *json, const struct test_case *c,
        enum result result, const char *why, size_t number)
{
    if (number > 1) fputs(",\n", json);
    fputs("{\"id\":", json); json_string(json, c->id);
    fputs(",\"requirement_id\":", json); json_string(json, c->requirement);
    fputs(",\"source\":", json); json_string(json, c->source);
    fputs(",\"strength\":", json); json_string(json, c->strength);
    fputs(",\"profile\":", json); json_string(json, c->profile);
    fputs(",\"status\":", json); json_string(json, result_name(result));
    fputs(",\"execution\":", json); json_string(json, test_execution_name());
    fputs(",\"coverage\":", json); json_string(json, c->coverage);
    fputs(",\"oracle_class\":", json); json_string(json, c->oracle_class);
    fputs(",\"reason\":", json); json_string(json, why);
    fputs("}", json);
    fflush(json);
}

/* Flush buffered output before deciding whether the run succeeded. */
static int report_stdout_failed(void)
{
    if (fflush(stdout) == EOF || ferror(stdout)) {
        fputs("Cannot write test output to stdout\n", stderr);
        return 1;
    }
    return 0;
}

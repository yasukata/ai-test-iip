/* Case registry and TAP/JSON reporting. Diagnostics from children go to stderr. */
struct test_case {
    enum result (*run)(const char **);
    const char *id, *description, *requirement, *source, *strength, *profile, *coverage;
};
/* A separate harness executable may supply deterministic reporting cases. */
#ifndef TEST_CASE_REGISTRY
#define TEST_CASE_REGISTRY "test_cases.h"
#endif
#include TEST_CASE_REGISTRY

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

static int profile_enabled(const char *p, int tfo, int strict, int blake)
{
    if (!strcmp(p, "tfo")) return tfo;
    if (!strcmp(p, "strict-api")) return strict;
    if (!strcmp(p, "blake2")) return blake;
    return 1;
}

static int main_usage(void)
{
    fprintf(stderr, "Usage: ai-test-iip [--list] [--case ID ...] [--json PATH] [--no-tfo] [--strict-api] [--blake2] [--conformance]\n"
        "       ai-test-iip --self-tests | --fast-open\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *selection[256], *json_path = NULL;
    size_t selected = 0, count = 0, emitted = 0;
    int list = 0, tfo = 1, only_tfo = 0, conformance = 0;
    int strict = 1, blake = 1;
    unsigned failed = 0, incomplete = 0, errors = 0, passed = 0, deviations = 0, skipped = 0;
    FILE *json = NULL;
    /* Keep runner selection and in-test profile guards enabled together. */
    if (setenv("IIP_TEST_STRICT_API_CONTRACT", "1", 1) ||
        setenv("IIP_TEST_BLAKE2_PROFILE", "1", 1)) {
        perror("setenv");
        return 2;
    }
    if (argc == 2 && !strcmp(argv[1], "--self-tests")) return run_self_tests();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--list")) list = 1;
        else if (!strcmp(argv[i], "--case") && i + 1 < argc && selected < ARRAY_LENGTH(selection)) selection[selected++] = argv[++i];
        else if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
        else if (!strcmp(argv[i], "--no-tfo")) tfo = 0;
        else if (!strcmp(argv[i], "--fast-open")) only_tfo = 1;
        else if (!strcmp(argv[i], "--conformance")) conformance = 1;
        else if (!strcmp(argv[i], "--strict-api")) { strict = 1; setenv("IIP_TEST_STRICT_API_CONTRACT", "1", 1); }
        else if (!strcmp(argv[i], "--blake2")) { blake = 1; setenv("IIP_TEST_BLAKE2_PROFILE", "1", 1); }
        else return main_usage();
    }
    for (size_t j = 0; j < selected; j++) {
        int found = 0;
        for (size_t i = 0; i < ARRAY_LENGTH(test_cases); i++) found |= !strcmp(selection[j], test_cases[i].id);
        if (!found) { fprintf(stderr, "Unknown case: %s\n", selection[j]); return 2; }
    }
    bool enabled[ARRAY_LENGTH(test_cases)];
    for (size_t i = 0; i < ARRAY_LENGTH(test_cases); i++) {
        const struct test_case *c = &test_cases[i];
        enabled[i] = !selected;
        for (size_t j = 0; j < selected; j++) if (!strcmp(selection[j], c->id)) enabled[i] = true;
        if (only_tfo && strncmp(c->id, "TFO-", 4)) enabled[i] = false;
        if (!enabled[i]) continue;
        count++;
        if (list) printf("%s\t%s\t%s\t%s\n", c->id, c->profile, c->source, c->description);
    }
    if (list) return 0;
    if (!count) return main_usage();
    if (json_path && !(json = fopen(json_path, "w"))) { perror(json_path); return 2; }
    if (json) fprintf(json, "{\"schema_version\":1,\"ledger_sha256\":\"%s\",\"scope\":\"README.md#evaluation-scope\",\"configuration\":{\"tfo\":%s,\"strict_api\":%s,\"blake2\":%s},\"cases\":[\n", TEST_LEDGER_SHA256, tfo ? "true" : "false", strict ? "true" : "false", blake ? "true" : "false");
    printf("TAP version 13\n1..%zu\n", count);
    for (size_t i = 0; i < ARRAY_LENGTH(test_cases); i++) {
        if (!enabled[i]) continue;
        const struct test_case *c = &test_cases[i];
        const char *why = NULL;
        enum result r;
        if ((!tfo && !strncmp(c->id, "TFO-", 4)) || !profile_enabled(c->profile, tfo, strict, blake)) {
            r = RESULT_SKIP; why = "explicitly disabled optional profile";
        } else r = run_isolated_test(c->run, &why);
        if (r == RESULT_FAIL && !strcmp(c->strength, "SHOULD") && !test_process_failed) r = RESULT_TODO;
        if (r == RESULT_TODO && strcmp(c->strength, "SHOULD")) {
            r = RESULT_INCONCLUSIVE; /* Mixed mandatory/recommended or policy-dependent observation. */
        }
        if (r == RESULT_SKIP && (!why || !*why)) { r = RESULT_ERROR; why = "missing applicability reason"; }
        if (r == RESULT_FAIL) failed++;
        else if (r == RESULT_INCONCLUSIVE) incomplete++;
        else if (r == RESULT_ERROR) errors++;
        else if (r == RESULT_PASS) passed++;
        else if (r == RESULT_TODO) deviations++;
        else skipped++;
        emitted++;
        printf("%s %zu - %s %s", (r == RESULT_PASS || r == RESULT_SKIP) ? "ok" : "not ok", emitted, c->id, c->description);
        if (r == RESULT_SKIP) printf(" # SKIP %s", why);
        else if (r == RESULT_TODO) printf(" # TODO recommendation deviation: %s", why ? why : "see diagnostics");
        else if (r != RESULT_PASS) printf(" - [%s] %s", result_name(r), why ? why : "assertion or predicate failed; see diagnostics");
        putchar('\n'); fflush(stdout);
        if (json) {
            if (emitted > 1) fputs(",\n", json);
            fputs("{\"id\":", json); json_string(json,c->id);
            fputs(",\"requirement_id\":", json); json_string(json,c->requirement);
            fputs(",\"source\":", json); json_string(json,c->source);
            fputs(",\"strength\":", json); json_string(json,c->strength);
            fputs(",\"profile\":", json); json_string(json,c->profile);
            fputs(",\"status\":", json); json_string(json,result_name(r));
            fputs(",\"coverage\":", json); json_string(json,c->coverage);
            fputs(",\"reason\":", json); json_string(json,why);
            fputs("}", json); fflush(json);
        }
    }
    /* Case success is never promoted to comprehensive conformance. */
    int rc = errors ? 2 : (failed || incomplete) ? 1 : conformance ? 3 : 0;
    if (json) {
        fprintf(json, "\n],\"summary\":{\"pass\":%u,\"fail\":%u,\"not_applicable\":%u,\"deviation\":%u,\"inconclusive\":%u,\"error\":%u},\"conformance\":\"NOT_ESTABLISHED\",\"exit_code\":%d}\n", passed,failed,skipped,deviations,incomplete,errors,rc);
        if (ferror(json)) { fclose(json); return 2; }
        if (fclose(json)) return 2;
    }
    fprintf(stderr,"Case summary: %u PASS, %u FAIL, %u NOT_APPLICABLE, %u DEVIATION, %u INCONCLUSIVE, %u ERROR; conformance NOT_ESTABLISHED\n",passed,failed,skipped,deviations,incomplete,errors);
    return rc;
}

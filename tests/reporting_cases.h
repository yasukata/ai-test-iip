/* Private registry for reporting_harness.c; never part of the real ledger. */
#define TEST_LEDGER_SHA256 "synthetic-reporting-cases"

static enum result synthetic_pass(const char **why)
{
    *why = NULL;
    return RESULT_PASS;
}

static enum result synthetic_fail(const char **why)
{
    *why = "expected=1, actual=2";
    return RESULT_FAIL;
}

static enum result synthetic_skip(const char **why)
{
    *why = "not applicable to this fixture";
    return RESULT_SKIP;
}

static enum result synthetic_empty_skip(const char **why)
{
    *why = NULL;
    return RESULT_SKIP;
}

static enum result synthetic_todo(const char **why)
{
    *why = "recommendation differs";
    return RESULT_TODO;
}

static enum result synthetic_inconclusive(const char **why)
{
    *why = "insufficient evidence";
    return RESULT_INCONCLUSIVE;
}

static enum result synthetic_error(const char **why)
{
    *why = "fixture error";
    return RESULT_ERROR;
}

static enum result synthetic_invalid(const char **why)
{
    *why = NULL;
    return (enum result)99;
}

static enum result synthetic_signal(const char **why)
{
    (void)why;
    raise(SIGKILL);
    return RESULT_PASS;
}

static enum result synthetic_condition(const char **why)
{
    (void)why;
    test_condition_failed(__func__, __LINE__, "expected=%u, actual=%u", 1U, 2U);
    return RESULT_FAIL;
}

static enum result synthetic_require(const char **why)
{
    TEST_REQUIRE(why, 0, "expected=%u, actual=%u", 3U, 4U);
    return RESULT_PASS;
}

static enum result synthetic_escaped(const char **why)
{
    *why = "quoted \"reason\"\nnext\tfield\\end";
    return RESULT_FAIL;
}

/* Text that must remain data rather than TAP records or directives. */
static const char tap_special_reason[] =
    "first\nnot ok 999 - forged # SKIP ignored # TODO ignored\r\t\033[31m\177\\tail";

static enum result synthetic_tap_fail(const char **why)
{
    *why = tap_special_reason;
    return RESULT_FAIL;
}

static enum result synthetic_tap_skip(const char **why)
{
    *why = tap_special_reason;
    return RESULT_SKIP;
}

static enum result synthetic_tap_todo(const char **why)
{
    *why = tap_special_reason;
    return RESULT_TODO;
}

static const char status_text_reason[] = "observed - [ERROR] and - [INCONCLUSIVE] as text";

static enum result synthetic_status_words(const char **why)
{
    *why = status_text_reason;
    return RESULT_FAIL;
}

static enum result synthetic_status_error(const char **why)
{
    *why = status_text_reason;
    return RESULT_ERROR;
}

static enum result synthetic_status_inconclusive(const char **why)
{
    *why = status_text_reason;
    return RESULT_INCONCLUSIVE;
}

static const struct test_case test_cases[] = {
    { synthetic_pass, "PASS", "synthetic PASS", "TEST:PASS", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_fail, "FAIL", "synthetic FAIL", "TEST:FAIL", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_skip, "SKIP", "synthetic SKIP", "TEST:SKIP", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_todo, "TODO", "synthetic TODO", "TEST:TODO", "tests/reporting_cases.h", "SHOULD", "base", "partial" },
    { synthetic_todo, "MANDATORY-TODO", "synthetic MANDATORY-TODO", "TEST:MANDATORY-TODO", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_fail, "SHOULD-FAIL", "synthetic SHOULD-FAIL", "TEST:SHOULD-FAIL", "tests/reporting_cases.h", "SHOULD", "base", "partial" },
    { synthetic_inconclusive, "INCONCLUSIVE", "synthetic INCONCLUSIVE", "TEST:INCONCLUSIVE", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_error, "ERROR", "synthetic ERROR", "TEST:ERROR", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_invalid, "INVALID", "synthetic INVALID", "TEST:INVALID", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_signal, "SIGNAL", "synthetic SIGNAL", "TEST:SIGNAL", "tests/reporting_cases.h", "SHOULD", "base", "partial" },
    { synthetic_condition, "CONDITION", "synthetic CONDITION", "TEST:CONDITION", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_require, "REQUIRE", "synthetic REQUIRE", "TEST:REQUIRE", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_escaped, "ESCAPED", "synthetic ESCAPED", "TEST:ESCAPED", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_empty_skip, "EMPTY-SKIP", "synthetic EMPTY-SKIP", "TEST:EMPTY-SKIP", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_tap_fail, "TAP-FAIL", "description\n # TODO fake", "TEST:TAP-FAIL", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_tap_skip, "TAP-SKIP", "description\n # TODO fake", "TEST:TAP-SKIP", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_tap_todo, "TAP-TODO", "description\n # TODO fake", "TEST:TAP-TODO", "tests/reporting_cases.h", "SHOULD", "base", "partial" },
    { synthetic_pass, "STATUS-TEXT-PASS", "description - [ERROR] is text", "TEST:STATUS-TEXT-PASS", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_status_words, "STATUS-TEXT-FAIL", "description - [INCONCLUSIVE] is text", "TEST:STATUS-TEXT-FAIL", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_status_error, "STATUS-TEXT-ERROR", "description - [INCONCLUSIVE] is text", "TEST:STATUS-TEXT-ERROR", "tests/reporting_cases.h", "MUST", "base", "partial" },
    { synthetic_status_inconclusive, "STATUS-TEXT-INCONCLUSIVE", "description - [ERROR] is text", "TEST:STATUS-TEXT-INCONCLUSIVE", "tests/reporting_cases.h", "MUST", "base", "partial" },
};

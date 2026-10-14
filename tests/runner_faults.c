/* Inject infrastructure faults without modifying any target-stack behavior. */
#define main harness_program_main
#include "../main.c"
#undef main

static enum result overflow_case(const char **why)
{
    (void)why;
    struct test_state state = { 0 };
    for (unsigned i = 0; i <= ARRAY_LENGTH(state.events); i++)
        test_event_append(&state, TEST_EVENT_CALLBACK, 0, NULL, 0, 0, 0, 0);
    return RESULT_PASS;
}

int main(void)
{
    const char *why = NULL;
    assert(run_isolated_test(overflow_case, &why) == RESULT_ERROR);
    assert(why && strstr(why, "overflow"));
    return 0;
}

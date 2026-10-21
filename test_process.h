/* Shared isolated execution for protocol cases and harness self-tests. */
#include <fcntl.h>
#include <sys/mman.h>

/*
 * RESULT_TODO is a recommendation deviation only when the ledger declares
 * SHOULD. Other uses become INCONCLUSIVE; mandatory failures stay failures.
 */
enum result { RESULT_PASS, RESULT_FAIL, RESULT_SKIP, RESULT_TODO, RESULT_INCONCLUSIVE, RESULT_ERROR };

/* A stack assertion or hang is a failed test, and must not hide later tests. */
static int test_process_failed;
/* Separate process completion from protocol verdicts. Sticky within one case
 * so nested isolated runs cannot hide an earlier timeout or signal. */
enum test_execution_kind {
    TEST_EXEC_NORMAL, TEST_EXEC_TIMEOUT, TEST_EXEC_SIGNAL,
    TEST_EXEC_EXIT_ERROR, TEST_EXEC_MISSING_REPORT, TEST_EXEC_ERROR,
    TEST_EXEC_NOT_RUN
};
static enum test_execution_kind test_execution;
static void test_execution_failed(enum test_execution_kind kind)
{
    if (test_execution == TEST_EXEC_NORMAL) test_execution = kind;
}
static const char *test_setup_error;
static char test_failure_detail[512];
static char *test_step_detail;

/* Shared with the parent so a signal or sanitizer exit retains the last step.
 * Nested isolated runs get their own mapping. */
static void test_step(const char *name)
{
    if (test_step_detail) snprintf(test_step_detail, 128, "%s", name);
}

static volatile sig_atomic_t isolated_group;
static void interrupt_isolated_group(int signum)
{
    pid_t child = isolated_group;
    if (child > 0) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    _exit(128 + signum);
}

/* Always reap a child when a timeout or a parent-side wait error interrupts it. */
static int kill_and_reap(pid_t child, int *status)
{
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    pid_t waited;
    do { waited = waitpid(child, status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child;
}

static int wait_isolated_child(pid_t child, unsigned timeout_seconds,
        int *status, int *timed_out)
{
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) {
        kill_and_reap(child, status);
        return 0;
    }
    for (;;) {
        pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child) return 1;
        if (waited < 0 && errno != EINTR) {
            kill_and_reap(child, status);
            return 0;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now)) {
            kill_and_reap(child, status);
            return 0;
        }
        /* Give the child's alarm one second to finish before enforcing a
         * deadline even if the test disabled or intercepted SIGALRM. */
        time_t deadline = start.tv_sec + timeout_seconds + 1;
        if (now.tv_sec > deadline || (now.tv_sec == deadline && now.tv_nsec >= start.tv_nsec)) {
            *timed_out = 1;
            return kill_and_reap(child, status);
        }
        const struct timespec pause_time = { 0, 1000000L };
        nanosleep(&pause_time, NULL);
    }
}

/* Both callback forms use the same report pipe and parent-side watchdog. */
static enum result run_isolated(enum result (*run)(const char **),
        void (*self_test)(void), const char **why, unsigned timeout_seconds)
{
    struct child_result { enum result result; char why[512]; enum test_execution_kind execution; } report = { RESULT_FAIL, { 0 }, TEST_EXEC_NORMAL };
    static char reason[512];
    assert((run != NULL) != (self_test != NULL));
    assert(timeout_seconds > 0);
    test_process_failed = 0;
    int channel[2], status;
    fflush(NULL);
    if (pipe(channel)) { *why = "cannot create result pipe"; test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR; }
    /* A missing report must not block if a descendant inherited the pipe. */
    if (fcntl(channel[0], F_SETFL, O_NONBLOCK) < 0) {
        close(channel[0]); close(channel[1]);
        *why = "cannot configure result pipe";
        test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR;
    }
    char *step = mmap(NULL, 128, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (step == MAP_FAILED) {
        close(channel[0]); close(channel[1]);
        *why = "cannot allocate shared test step";
        test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR;
    }
    sigset_t blocked, previous_mask;
    struct sigaction action = { 0 }, previous_int, previous_term;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT); sigaddset(&blocked, SIGTERM);
    sigprocmask(SIG_BLOCK, &blocked, &previous_mask);
    action.sa_handler = interrupt_isolated_group;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGINT); sigaddset(&action.sa_mask, SIGTERM);
    sigaction(SIGINT, &action, &previous_int);
    sigaction(SIGTERM, &action, &previous_term);
    pid_t child = fork();
    if (child < 0) {
        sigaction(SIGINT, &previous_int, NULL); sigaction(SIGTERM, &previous_term, NULL);
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        munmap(step, 128);
        close(channel[0]); close(channel[1]); *why = "cannot fork test"; test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR; }
    if (!child) {
        test_step_detail = step;
        close(channel[0]);
        if (setpgid(0, 0)) _exit(125);
        sigaction(SIGINT, &previous_int, NULL); sigaction(SIGTERM, &previous_term, NULL);
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) _exit(125);
        harness_event_overflow = 0;
        test_failure_detail[0] = 0;
        test_setup_error = NULL;
        alarm(timeout_seconds);
        const char *detail = NULL;
        if (run) report.result = run(&detail);
        else { self_test(); report.result = RESULT_PASS; }
        if ((report.result == RESULT_FAIL || report.result == RESULT_TODO ||
                report.result == RESULT_INCONCLUSIVE || report.result == RESULT_ERROR) &&
                (!detail || !*detail) && test_failure_detail[0])
            detail = test_failure_detail;
        if (test_setup_error) { report.result = RESULT_ERROR; detail = test_setup_error; }
        if (harness_event_overflow) { report.result = RESULT_ERROR; detail = "event log overflow; observations incomplete"; }
        report.execution = test_execution;
        if (detail) snprintf(report.why, sizeof(report.why), "%s", detail);
        fflush(NULL);
        ssize_t n = write(channel[1], &report, sizeof(report));
        close(channel[1]);
        _exit(n == sizeof(report) ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    /* Either side may establish the group first. */
    (void)setpgid(child, child);
    isolated_group = child;
    sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    close(channel[1]);
    int timed_out = 0;
    int waited = wait_isolated_child(child, timeout_seconds, &status, &timed_out);
    kill(-child, SIGKILL);
    sigprocmask(SIG_BLOCK, &blocked, NULL);
    isolated_group = 0;
    sigaction(SIGINT, &previous_int, NULL); sigaction(SIGTERM, &previous_term, NULL);
    sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    if (!waited) {
        close(channel[0]);
        munmap(step, 128);
        *why = "cannot wait for test process";
        test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR;
    }
    ssize_t n;
    do { n = read(channel[0], &report, sizeof(report)); } while (n < 0 && errno == EINTR);
    close(channel[0]);
    if (!WIFEXITED(status) || WEXITSTATUS(status) || n != sizeof(report)) {
        if (timed_out || (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM)) {
            test_execution_failed(TEST_EXEC_TIMEOUT);
            snprintf(reason, sizeof(reason), "test process timed out after %u second%s",
                timeout_seconds, timeout_seconds == 1 ? "" : "s");
        } else {
            test_execution_failed(WIFSIGNALED(status) ? TEST_EXEC_SIGNAL :
                WIFEXITED(status) && WEXITSTATUS(status) ? TEST_EXEC_EXIT_ERROR : TEST_EXEC_MISSING_REPORT);
            snprintf(reason, sizeof(reason), "test process failed (signal=%d, exit=%d)", WIFSIGNALED(status) ? WTERMSIG(status) : 0, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
        if (step[0]) {
            size_t used = strlen(reason);
            snprintf(reason + used, sizeof(reason) - used, "; step=%s", step);
        }
        munmap(step, 128);
        *why = reason;
        test_process_failed = 1;
        return WIFSIGNALED(status) ? RESULT_FAIL : RESULT_ERROR;
    }
    munmap(step, 128);
    if (report.result < RESULT_PASS || report.result > RESULT_ERROR) { *why = "invalid child result"; test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR; }
    if (report.execution < TEST_EXEC_NORMAL || report.execution > TEST_EXEC_NOT_RUN) {
        *why = "invalid child execution kind";
        test_execution_failed(TEST_EXEC_ERROR); return RESULT_ERROR;
    }
    if (report.execution != TEST_EXEC_NORMAL) test_execution_failed(report.execution);
    snprintf(reason, sizeof(reason), "%s", report.why);
    *why = reason[0] ? reason : NULL;
    return report.result;
}

static enum result run_isolated_test(enum result (*run)(const char **), const char **why)
{
    return run_isolated(run, NULL, why, 30);
}

static enum result run_isolated_self_test(void (*run)(void), const char **why,
        unsigned timeout_seconds)
{
    return run_isolated(NULL, run, why, timeout_seconds);
}


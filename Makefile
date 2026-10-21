CC ?= cc
PYTHON ?= python3
TEST_OUTPUT_FLAGS ?=
CFLAGS ?= -O2 -g
WARNINGS = -Wall -Wextra -Wpedantic
SANITIZER_CFLAGS = -O1 -g -fno-omit-frame-pointer
ASAN_FLAGS = -fsanitize=address
UBSAN_FLAGS = -fsanitize=undefined
TEST_HEADERS = $(wildcard test_*.h) conformance_tests.h
TEST_SOURCES = $(TEST_HEADERS) main.c test_api.c test_backend.c iip/main.c blake2s-ref.c blake2.h blake2-impl.h

.PHONY: all check check-asan check-ubsan check-sanitizers clean

all: ai-test-iip

ai-test-iip: $(TEST_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=gnu11 -o $@ main.c

ai-test-iip-asan: $(TEST_SOURCES)
	$(CC) $(CPPFLAGS) $(SANITIZER_CFLAGS) $(WARNINGS) $(ASAN_FLAGS) \
		-std=gnu11 -o $@ main.c

ai-test-iip-ubsan: $(TEST_SOURCES)
	$(CC) $(CPPFLAGS) $(SANITIZER_CFLAGS) $(WARNINGS) $(UBSAN_FLAGS) \
		-std=gnu11 -o $@ main.c

check: check-registry ai-test-iip
	$(PYTHON) run_tests.py $(TEST_OUTPUT_FLAGS) -- ./ai-test-iip

check-asan: check-registry ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(PYTHON) run_tests.py $(TEST_OUTPUT_FLAGS) --log test-results-asan.log -- ./ai-test-iip-asan

check-ubsan: check-registry ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(PYTHON) run_tests.py $(TEST_OUTPUT_FLAGS) --log test-results-ubsan.log -- ./ai-test-iip-ubsan

check-sanitizers: check-asan check-ubsan

clean:
	$(RM) ai-test-iip ai-test-iip-asan ai-test-iip-ubsan

.PHONY: registry check-registry check-harness check-mutations check-conformance
registry:
	$(PYTHON) scripts/generate_cases.py

check-registry:
	$(PYTHON) scripts/generate_cases.py --check

check-harness: check-registry ai-test-iip
	./ai-test-iip --self-tests
	$(PYTHON) -m unittest discover -s tests -v
	@set -eu; test_tmp=$$(mktemp -d); trap 'rm -rf "$$test_tmp"' EXIT HUP INT TERM; \
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=gnu11 -o "$$test_tmp/runner-faults" tests/runner_faults.c; \
	"$$test_tmp/runner-faults"

# Exercise harness validators independently of target-stack conformance failures.
.PHONY: check-harness-asan check-harness-ubsan check-harness-sanitizers
check-harness-asan: check-registry
	@set -eu; test_tmp=$$(mktemp -d); trap 'rm -rf "$$test_tmp"' EXIT HUP INT TERM; \
	$(CC) $(CPPFLAGS) $(SANITIZER_CFLAGS) $(ASAN_FLAGS) $(WARNINGS) -std=gnu11 -o "$$test_tmp/runner-faults" tests/runner_faults.c; \
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$$test_tmp/runner-faults"

check-harness-ubsan: check-registry
	@set -eu; test_tmp=$$(mktemp -d); trap 'rm -rf "$$test_tmp"' EXIT HUP INT TERM; \
	$(CC) $(CPPFLAGS) $(SANITIZER_CFLAGS) $(UBSAN_FLAGS) $(WARNINGS) -std=gnu11 -o "$$test_tmp/runner-faults" tests/runner_faults.c; \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$$test_tmp/runner-faults"

check-harness-sanitizers: check-harness-asan check-harness-ubsan

check-mutations: check-registry
	$(PYTHON) scripts/check_mutations.py

check-conformance: check-registry ai-test-iip
	$(PYTHON) scripts/capture_run.py --output artifacts/conformance -- ./ai-test-iip --conformance

.PHONY: check-phase4 check-phase4-asan check-phase4-ubsan
check-phase4: check-registry ai-test-iip
	$(PYTHON) scripts/run_phase.py --phase 4 --output artifacts/phase4/normal ./ai-test-iip

check-phase4-asan: check-registry ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(PYTHON) scripts/run_phase.py --phase 4 --output artifacts/phase4/asan ./ai-test-iip-asan

check-phase4-ubsan: check-registry ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(PYTHON) scripts/run_phase.py --phase 4 --output artifacts/phase4/ubsan ./ai-test-iip-ubsan

.PHONY: check-phase6 check-phase6-asan check-phase6-ubsan
check-phase6: check-registry ai-test-iip
	$(PYTHON) scripts/run_phase.py --phase 6 --output artifacts/phase6/normal ./ai-test-iip

check-phase6-asan: check-registry ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(PYTHON) scripts/run_phase.py --phase 6 --output artifacts/phase6/asan ./ai-test-iip-asan

check-phase6-ubsan: check-registry ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(PYTHON) scripts/run_phase.py --phase 6 --output artifacts/phase6/ubsan ./ai-test-iip-ubsan

.PHONY: check-phase6-mutations
check-phase6-mutations: check-registry
	$(PYTHON) scripts/check_mutations.py --output artifacts/phase6/mutations \
		--experiment flow_rwnd_unlimited --experiment flow_cwnd_unlimited \
		--experiment flow_ca_frozen --experiment flow_loss_window_two

.PHONY: check-phase7 check-phase7-asan check-phase7-ubsan
check-phase7: check-registry ai-test-iip
	$(PYTHON) scripts/run_phase.py --phase 7 --output artifacts/phase7/normal ./ai-test-iip

check-phase7-asan: check-registry ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(PYTHON) scripts/run_phase.py --phase 7 --output artifacts/phase7/asan ./ai-test-iip-asan

check-phase7-ubsan: check-registry ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(PYTHON) scripts/run_phase.py --phase 7 --output artifacts/phase7/ubsan ./ai-test-iip-ubsan

.PHONY: check-phase7-mutations
check-phase7-mutations: check-registry
	$(PYTHON) scripts/check_mutations.py --output artifacts/phase7/mutations \
		--experiment life_missing_close_callback --experiment life_retained_connection \
		--experiment life_retained_sent

.PHONY: check-oracles check-phase8 check-phase8-asan check-phase8-ubsan check-phase8-mutations
check-oracles: check-registry
	$(PYTHON) scripts/audit_oracles.py

check-phase8: check-oracles ai-test-iip
	$(PYTHON) scripts/run_phase.py --phase 8 --output artifacts/phase8/normal ./ai-test-iip

check-phase8-asan: check-oracles ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(PYTHON) scripts/run_phase.py --phase 8 --output artifacts/phase8/asan ./ai-test-iip-asan

check-phase8-ubsan: check-oracles ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(PYTHON) scripts/run_phase.py --phase 8 --output artifacts/phase8/ubsan ./ai-test-iip-ubsan

check-phase8-mutations: check-registry
	$(PYTHON) scripts/check_mutations.py --output artifacts/phase8/mutations \
		--experiment oracle_checksum_disabled --experiment oracle_payload_suppressed

.PHONY: check-phase9 check-phase9-asan check-phase9-ubsan check-phase9-mutations
check-phase9: check-registry ai-test-iip
	$(PYTHON) scripts/run_phase.py --phase 9 --output artifacts/phase9/normal ./ai-test-iip

check-phase9-asan: check-registry ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(PYTHON) scripts/run_phase.py --phase 9 --output artifacts/phase9/asan ./ai-test-iip-asan

check-phase9-ubsan: check-registry ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $(PYTHON) scripts/run_phase.py --phase 9 --output artifacts/phase9/ubsan ./ai-test-iip-ubsan

check-phase9-mutations: check-registry
	$(PYTHON) scripts/check_mutations.py --phase9 --output artifacts/phase9/mutations

CC ?= cc
PYTHON ?= python3
TEST_OUTPUT_FLAGS ?=
CFLAGS ?= -O2 -g
WARNINGS = -Wall -Wextra -Wpedantic
SANITIZER_CFLAGS = -O1 -g -fno-omit-frame-pointer
ASAN_FLAGS = -fsanitize=address
UBSAN_FLAGS = -fsanitize=undefined
TEST_SOURCES = test_runner.h test_cases.h conformance_tests.h main.c test_api.c test_api.h test_backend.c test_backend.h test_wire.h iip/main.c blake2s-ref.c blake2.h blake2-impl.h

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
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=gnu11 -o /tmp/ai-test-iip-runner-faults tests/runner_faults.c
	/tmp/ai-test-iip-runner-faults

check-mutations: check-registry
	$(PYTHON) scripts/check_mutations.py

check-conformance: check-registry ai-test-iip
	$(PYTHON) scripts/capture_run.py --output artifacts/conformance -- ./ai-test-iip --conformance

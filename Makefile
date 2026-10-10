CC ?= cc
CFLAGS ?= -O2 -g
WARNINGS = -Wall -Wextra -Wpedantic
SANITIZER_CFLAGS = -O1 -g -fno-omit-frame-pointer
ASAN_FLAGS = -fsanitize=address
UBSAN_FLAGS = -fsanitize=undefined
TEST_SOURCES = main.c iip/main.c blake2s-ref.c blake2.h blake2-impl.h

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

check: ai-test-iip
	./ai-test-iip

check-asan: ai-test-iip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./ai-test-iip-asan

check-ubsan: ai-test-iip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./ai-test-iip-ubsan

check-sanitizers: check-asan check-ubsan

clean:
	$(RM) ai-test-iip ai-test-iip-asan ai-test-iip-ubsan

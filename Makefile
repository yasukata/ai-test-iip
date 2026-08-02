CC ?= cc
CFLAGS ?= -O2 -g
LWIP_DIR ?= lwip-2.2.1
CPPFLAGS += -I. -I$(LWIP_DIR)/src/include \
	-I$(LWIP_DIR)/contrib/ports/unix/port/include
WARNINGS = -Wall -Wextra -Wpedantic
SANITIZER_CFLAGS = -O1 -g -fno-omit-frame-pointer
ASAN_FLAGS = -fsanitize=address
UBSAN_FLAGS = -fsanitize=undefined

LWIP_CORE = $(wildcard $(LWIP_DIR)/src/core/*.c)
LWIP_IPV4 = $(wildcard $(LWIP_DIR)/src/core/ipv4/*.c)
LWIP_NETIF = $(LWIP_DIR)/src/netif/ethernet.c
LWIP_SOURCES = $(LWIP_CORE) $(LWIP_IPV4) $(LWIP_NETIF)

.PHONY: all check check-lwip check-lwip-impairment \
	check-lwip-impairment-full check-lwip-test check-asan check-ubsan \
	check-sanitizers clean

all: ai-test-iip ai-test-iip-lwip

ai-test-iip: main.c iip/main.c blake2s-ref.c blake2.h blake2-impl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=gnu11 -o $@ main.c

ai-test-iip-lwip: main.c iip/main.c lwipopts.h $(LWIP_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=gnu11 \
		-DIIP_LWIP_INTEROP -o $@ main.c $(LWIP_SOURCES)

ai-test-iip-lwip-asan: main.c iip/main.c lwipopts.h $(LWIP_SOURCES)
	$(CC) $(CPPFLAGS) $(SANITIZER_CFLAGS) $(WARNINGS) $(ASAN_FLAGS) \
		-std=gnu11 -DIIP_LWIP_INTEROP -o $@ main.c $(LWIP_SOURCES)

ai-test-iip-lwip-ubsan: main.c iip/main.c lwipopts.h $(LWIP_SOURCES)
	$(CC) $(CPPFLAGS) $(SANITIZER_CFLAGS) $(WARNINGS) $(UBSAN_FLAGS) \
		-std=gnu11 -DIIP_LWIP_INTEROP -o $@ main.c $(LWIP_SOURCES)

check-lwip: ai-test-iip-lwip
	./ai-test-iip-lwip --lwip-only

check-lwip-impairment: ai-test-iip-lwip
	./ai-test-iip-lwip --lwip-impairment

check-lwip-impairment-full: ai-test-iip-lwip
	./ai-test-iip-lwip --lwip-impairment-full

check-lwip-test: ai-test-iip-lwip
	@test -n "$(LWIP_TEST)" || \
		{ echo "set LWIP_TEST to a test ID"; exit 2; }
	./ai-test-iip-lwip --lwip-test "$(LWIP_TEST)"

check: check-lwip check-lwip-impairment

check-asan: ai-test-iip-lwip-asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		./ai-test-iip-lwip-asan --lwip-only
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		./ai-test-iip-lwip-asan --lwip-impairment

check-ubsan: ai-test-iip-lwip-ubsan
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		./ai-test-iip-lwip-ubsan --lwip-only
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		./ai-test-iip-lwip-ubsan --lwip-impairment

check-sanitizers: check-asan check-ubsan

clean:
	$(RM) ai-test-iip ai-test-iip-lwip ai-test-iip-lwip-asan \
		ai-test-iip-lwip-ubsan

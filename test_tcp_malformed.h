/* Receive checksum, malformed input, boundary values, and packet fuzzing.
 * Included in dependency order by test_tcp.h.
 */

static enum result test_rx_checksum(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	void *pkt;
	pid_t child;
	int ok;
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.corrupt_tcp_checksum = 1;
	pkt = build_tcp_packet(&spec, &f.state);
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child) {
		fixture_deliver(&f, pkt);
		_exit(f.state.payload_chunk_count == 0 && f.conn->seq_next_expected == 0 ? 0 : 1);
	}
	ok = wait_test_child(child, 1000);
	iip_ops_pkt_free(pkt, &f.state);
	return ok ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_arbitrary_segment_options(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	const uint8_t unknown[] = { 253, 4, 0xaa, 0xbb };
	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	tcp_packet_add_nop(&spec);
	tcp_packet_add_raw_option(&spec, unknown, sizeof(unknown));
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	return f.state.payload_chunk_count == 1 && f.conn->seq_next_expected == 1
		? RESULT_PASS : RESULT_FAIL;
}

static int invalid_tcp_header_length_case(uint8_t data_offset_words)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	void *pkt;
	uint16_t flags;
	uint8_t state_before;
	uint32_t seq_before;
	unsigned int payload_before;

	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &f.state);

	/*
	 * Data Offset is expressed in 32-bit words.  Values below five
	 * describe a TCP header shorter than the mandatory 20-byte base
	 * header.  Larger values may describe a header that extends beyond
	 * the containing IPv4 payload.  Keep every other flag unchanged and
	 * recompute the checksum so rejection is specifically attributable to
	 * the malformed TCP header length rather than a checksum failure.
	 */
	flags = ii_ntohs(PB_TCP(pkt)->flags);
	flags = (uint16_t)((flags & 0x0fffU) |
			((uint16_t)data_offset_words << 12));
	PB_TCP(pkt)->flags = ii_htons(flags);
	update_tcp_checksum(pkt);

	state_before = f.conn->state;
	seq_before = f.conn->seq_next_expected;
	payload_before = f.state.payload_chunk_count;
	fixture_deliver(&f, pkt);

	TEST_CONDITION(f.conn->state == state_before,
			"Data Offset=%u changed state: expected=%u actual=%u",
			data_offset_words, state_before, f.conn->state);
	TEST_CONDITION(f.conn->seq_next_expected == seq_before,
			"Data Offset=%u advanced RCV.NXT: expected=%u actual=%u",
			data_offset_words, seq_before, f.conn->seq_next_expected);
	TEST_CONDITION(f.state.payload_chunk_count == payload_before,
			"Data Offset=%u delivered payload: before=%u after=%u",
			data_offset_words, payload_before,
			f.state.payload_chunk_count);
	TEST_CONDITION(f.state.out_cnt == 0,
			"Data Offset=%u generated %u unexpected output packet(s)",
			data_offset_words, f.state.out_cnt);
	TEST_CONDITION(test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_PAYLOAD) == 0,
			"Data Offset=%u invoked the payload callback", data_offset_words);
	return 1;
}

static int invalid_tcp_header_length_scenario(void)
{
	static const uint8_t invalid_offsets[] = {
		0, 1, 2, 3, 4, /* shorter than the 20-byte TCP base header */
		6, 15,         /* longer than this packet's TCP segment */
	};
	unsigned int i;

	for (i = 0; i < ARRAY_LENGTH(invalid_offsets); i++)
		if (!invalid_tcp_header_length_case(invalid_offsets[i]))
			return 0;
	return 1;
}

static enum result test_invalid_tcp_header_length(const char **why)
{
	pid_t child;

	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(invalid_tcp_header_length_scenario() ? 0 : 1);
	if (!wait_test_child(child, 2000)) {
		*why = "invalid TCP Data Offset was accepted or caused a crash/hang";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static int malformed_input_normal_controls(void)
{
	struct fixture checksum, full_length, base_header, extended_header;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	const uint8_t options[] = { 1, 1, 0, 0 };
	void *pkt;

	/* Valid checksums must be accepted before corrupt-checksum rejection is trusted. */
	if (!fixture_init(&checksum))
		return 0;
	fixture_incoming_spec(&checksum, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &checksum.state);
	if (!ip4_checksum_valid(pkt) || !checksum_valid(pkt))
		return 0;
	fixture_deliver(&checksum, pkt);
	if (checksum.state.payload_chunk_count != 1 ||
			checksum.conn->seq_next_expected != 1)
		return 0;

	/* A physically complete IPv4/TCP packet must pass the truncation controls. */
	if (!fixture_init(&full_length))
		return 0;
	fixture_incoming_spec(&full_length, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &full_length.state);
	if (iip_ops_pkt_get_len(pkt, &full_length.state) !=
			14 + sizeof(struct iip_ip4_hdr) +
			sizeof(struct iip_tcp_hdr) + sizeof(payload))
		return 0;
	fixture_deliver(&full_length, pkt);
	if (full_length.state.payload_chunk_count != 1)
		return 0;

	/* Data Offset 5 is the valid minimum TCP header length. */
	if (!fixture_init(&base_header))
		return 0;
	fixture_incoming_spec(&base_header, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &base_header.state);
	if (PB_TCP_HDR_LEN(pkt) != 5)
		return 0;
	fixture_deliver(&base_header, pkt);
	if (base_header.state.payload_chunk_count != 1)
		return 0;

	/* Data Offset 6 is valid when four option bytes are physically present. */
	if (!fixture_init(&extended_header))
		return 0;
	fixture_incoming_spec(&extended_header, &spec, 0, payload, sizeof(payload));
	tcp_packet_add_raw_option(&spec, options, sizeof(options));
	pkt = build_tcp_packet(&spec, &extended_header.state);
	if (PB_TCP_HDR_LEN(pkt) != 6)
		return 0;
	fixture_deliver(&extended_header, pkt);
	return extended_header.state.payload_chunk_count == 1 &&
		extended_header.conn->seq_next_expected == 1;
}

static int malformed_checksum_cases(void)
{
	unsigned int i;
	for (i = 0; i < 2; i++) {
		struct fixture f;
		struct tcp_packet_spec spec;
		const uint8_t payload[] = { 0x5a };
		void *pkt;
		if (!fixture_init(&f))
			return 0;
		fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
		pkt = build_tcp_packet(&spec, &f.state);
		if (i == 0)
			PB_IP4(pkt)->csum_be ^= ii_htons(1);
		else
			PB_TCP(pkt)->csum_be ^= ii_htons(1);
		fixture_deliver(&f, pkt);
		if (f.state.payload_chunk_count != 0 || f.conn->seq_next_expected != 0 ||
			f.state.out_cnt != 0)
			return 0;
	}
	return 1;
}

static int truncated_packet_case(uint16_t packet_len)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	void *pkt;
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &f.state);
	assert(packet_len < iip_ops_pkt_get_len(pkt, &f.state));
	iip_ops_pkt_set_len(pkt, packet_len, &f.state);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 && f.conn->seq_next_expected == 0 &&
		f.state.out_cnt == 0;
}

static int truncated_packet_cases(void)
{
	static const uint16_t lengths[] = {
		14,      /* Ethernet frame without any IPv4 header bytes. */
		14 + 19, /* IPv4 base header truncated by one byte. */
		14 + 20, /* Complete IPv4 header, no TCP bytes. */
		14 + 20 + 19, /* TCP base header truncated by one byte. */
		14 + 20 + 20, /* Payload declared by IPv4 but physically absent. */
	};
	unsigned int i;
	for (i = 0; i < ARRAY_LENGTH(lengths); i++)
		if (!truncated_packet_case(lengths[i]))
			return 0;
	return 1;
}

static int invalid_flag_combination_case(uint8_t tcp_flags)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	uint8_t state_before;
	uint32_t seq_before;
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags = tcp_flags;
	state_before = f.conn->state;
	seq_before = f.conn->seq_next_expected;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.conn->state == state_before,
			"flags=0x%02x changed state: expected=%u actual=%u",
			tcp_flags, state_before, f.conn->state);
	TEST_CONDITION(f.conn->seq_next_expected == seq_before,
			"flags=0x%02x advanced RCV.NXT: expected=%u actual=%u",
			tcp_flags, seq_before, f.conn->seq_next_expected);
	TEST_CONDITION(f.state.payload_chunk_count == 0,
			"flags=0x%02x delivered %u payload chunk(s)",
			tcp_flags, f.state.payload_chunk_count);
	return 1;
}

static int reset_flag_combination_case(uint8_t tcp_flags)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0x5a };
	uint8_t state_before;
	if (!fixture_init(&f))
		return 0;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	spec.tcp_flags = tcp_flags;
	state_before = f.conn->state;
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	TEST_CONDITION(f.state.payload_chunk_count == 0,
			"RST flags=0x%02x delivered %u payload chunk(s)",
			tcp_flags, f.state.payload_chunk_count);
	TEST_CONDITION(test_event_has_state_transition(&f.state, f.conn,
				state_before, II_TCP_STATE_CLOSED),
			"RST flags=0x%02x did not transition state %u -> CLOSED",
			tcp_flags, state_before);
	TEST_CONDITION(test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED) == 1,
			"RST flags=0x%02x produced %u closed callback(s); expected 1",
			tcp_flags, test_event_count(&f.state, TEST_EVENT_CALLBACK,
				TEST_CALLBACK_CLOSED));
	return 1;
}

static int invalid_flag_combination_cases(void)
{
	static const uint8_t invalid_combinations[] = {
		TEST_TCP_SYN | TEST_TCP_FIN,
	};
	static const uint8_t reset_combinations[] = {
		TEST_TCP_SYN | TEST_TCP_RST,
		TEST_TCP_FIN | TEST_TCP_RST,
		TEST_TCP_SYN | TEST_TCP_FIN | TEST_TCP_RST,
	};
	unsigned int i;
	for (i = 0; i < ARRAY_LENGTH(invalid_combinations); i++)
		if (!invalid_flag_combination_case(invalid_combinations[i]))
			return 0;
	/*
	 * RFC 9293 Section 3.10.7.4 checks RST before SYN and FIN in
	 * synchronized states.  An acceptable RST therefore resets the
	 * connection even when either of those flags is also present.
	 */
	for (i = 0; i < ARRAY_LENGTH(reset_combinations); i++)
		if (!reset_flag_combination_case(reset_combinations[i]))
			return 0;
	return 1;
}

static int mss_boundary_case(uint16_t advertised_mss)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	struct ii_pb *p;
	void *payload;
	uint32_t expected_seq;
	unsigned int total = 0;
	const uint16_t payload_len = advertised_mss == 1 ? 4 : 1600;

	if (!fixture_init(&f))
		return 0;
	f.conn->state = II_TCP_STATE_SYN_SENT;
	/* Exercise small MSS without Timestamp option overhead. */
	f.conn->flags &= ~II_TCP_CONN_FLAGS_OPT_SET_TS;
	fixture_incoming_spec(&f, &spec, 100, NULL, 0);
	spec.tcp_flags = TEST_TCP_SYN | TEST_TCP_ACK;
	spec.ack_seq = f.conn->seq + 1;
	tcp_packet_add_mss(&spec, advertised_mss);
	fixture_deliver(&f, build_tcp_packet(&spec, &f.state));
	if (f.state.payload_chunk_count != 0)
		return 0;
	/* Zero is a robustness case: rejection or a usable fallback is allowed.
	 * RFC 9293 does not prescribe retaining the configured initial MSS. */
	/* MSS 0 and MSS 1 are robustness cases; refusing such a connection
	 * is an acceptable defense, but an established connection must honor
	 * the advertised MSS (MUST-16). */
	if (advertised_mss <= 1 && f.conn->state != II_TCP_STATE_ESTABLISHED)
		return 1;
	if (f.conn->state != II_TCP_STATE_ESTABLISHED || !f.conn->mss)
		return 0;

	/* Check wire behavior, without prescribing how peer MSS is stored. */
	expected_seq = f.conn->seq;
	payload = iip_ops_pkt_alloc(&f.state);
	if (!payload)
		return 0;
	memset(iip_ops_pkt_get_data(payload, &f.state), 0x5a, payload_len);
	iip_ops_pkt_set_len(payload, payload_len, &f.state);
	test_api_push(f.ws, f.conn, payload, 0, 1, 0, 0, 0,
			NULL, 0, &f.state);
	free_output(&f.state);
	p = test_ring_end(f.ws, &f.conn->tx_ring, 0);
	if (!p || ii_tcp_xmit_queued_data_one(f.ws,
			test_conn_id(f.ws, f.conn), (uint32_t)(p - f.ws->pbs.array),
			0, p->tcp.payload_len, &f.state) != IIP_ERR_OK)
		return 0;
	for (unsigned int i = 0; i < f.state.out_cnt; i++) {
		void *pkt = f.state.out[i];
		uint16_t len = PB_TCP_PAYLOAD_LEN(pkt);
		if (!len || (advertised_mss && len > advertised_mss) ||
				ii_ntohs(PB_IP4(pkt)->len_be) > f.conn->path_mtu ||
				ii_ntohl(PB_TCP(pkt)->seq_be) != expected_seq ||
				!ip4_checksum_valid(pkt) || !checksum_valid(pkt))
			return 0;
		for (uint16_t j = 0; j < len; j++)
			if (PB_TCP_PAYLOAD(pkt)[j] != 0x5a)
				return 0;
		expected_seq += len;
		total += len;
	}
	return total == payload_len;
}

static int payload_length_boundary_cases(void)
{
	struct fixture empty, maximum;
	struct tcp_packet_spec spec;
	const struct test_event *payload_event;
	uint8_t *payload;
	const uint16_t maximum_payload =
		2048 - 8 * sizeof(long) - 14 - sizeof(struct iip_ip4_hdr) -
		sizeof(struct iip_tcp_hdr);
	if (!fixture_init(&empty) || !fixture_init(&maximum))
		return 0;
	fixture_incoming_spec(&empty, &spec, 0, NULL, 0);
	fixture_deliver(&empty, build_tcp_packet(&spec, &empty.state));
	if (empty.state.payload_chunk_count != 0 || empty.conn->seq_next_expected != 0)
		return 0;
	payload = malloc(maximum_payload);
	if (!payload)
		return 0;
	{
		uint16_t i;
		for (i = 0; i < maximum_payload; i++)
			payload[i] = (uint8_t)i;
	}
	fixture_incoming_spec(&maximum, &spec, 0, payload, maximum_payload);
	fixture_deliver(&maximum, build_tcp_packet(&spec, &maximum.state));
	free(payload);
	payload_event = test_event_nth(&maximum.state, TEST_EVENT_CALLBACK,
			TEST_CALLBACK_PAYLOAD, 0);
	return maximum.state.payload_chunk_count == 1 && payload_event &&
		payload_event->value[0] == maximum_payload &&
		maximum.state.payload_byte_count == maximum_payload &&
		maximum.conn->seq_next_expected == maximum_payload;
}

static int additional_malformed_boundary_scenario(void)
{
	int ok = 1;

	/* Positive controls prevent an always-drop implementation from passing. */
	TEST_ACCUMULATE(ok, malformed_input_normal_controls(),
			"positive controls failed: valid checksum, complete packet, or valid Data Offset was rejected");

	/* Do not short-circuit: exercise every malformed-input family. */
	TEST_ACCUMULATE(ok, malformed_checksum_cases(),
			"invalid IPv4 or TCP checksum changed connection state, delivered payload, or generated output");
	TEST_ACCUMULATE(ok, truncated_packet_cases(),
			"a physically truncated IPv4/TCP packet was not silently discarded");
	TEST_ACCUMULATE(ok, invalid_flag_combination_cases(),
			"SYN/FIN/RST flag precedence or reset notification was incorrect");
	TEST_ACCUMULATE(ok, mss_boundary_case(0),
			"MSS=0 was neither safely rejected nor handled with a usable fallback");
	TEST_ACCUMULATE(ok, mss_boundary_case(1),
			"MSS=1 handshake or one-octet payload segmentation failed");
	TEST_ACCUMULATE(ok,
			mss_boundary_case(UINT16_MAX),
			"MSS=65535 handshake or path-MTU-limited transmission failed");
	TEST_ACCUMULATE(ok, payload_length_boundary_cases(),
			"zero-length or maximum-length payload boundary handling failed");
	return ok;
}

static enum result test_additional_malformed_boundaries(const char **why)
{
	pid_t child;
	fflush(NULL);
	child = fork();
	assert(child >= 0);
	if (!child)
		_exit(additional_malformed_boundary_scenario() ? 0 : 1);
	if (!wait_test_child(child, 5000)) {
		*why = "checksum, truncation, flag, MSS, or payload boundary test failed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

struct fuzz_config {
	uint64_t seed;
	unsigned int cases;
	const char *failure_prefix;
};

static uint64_t fuzz_random(uint64_t *state)
{
	uint64_t x = *state;

	/* xorshift64*: compact, deterministic, and identical across platforms. */
	if (!x)
		x = 0x9e3779b97f4a7c15ULL;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 2685821657736338717ULL;
}

static struct fuzz_config fuzz_config_get(void)
{
	struct fuzz_config config = {
		0x4959502d46555a5aULL, /* "IYP-FUZZ" default seed. */
		64,
		"iip-fuzz-failure",
	};
	const char *value;
	char *end;
	unsigned long long parsed;

	value = getenv("IIP_FUZZ_SEED");
	if (value && *value) {
		parsed = strtoull(value, &end, 0);
		if (*end == '\0')
			config.seed = (uint64_t)parsed;
	}
	value = getenv("IIP_FUZZ_CASES");
	if (value && *value) {
		parsed = strtoull(value, &end, 0);
		if (*end == '\0' && parsed > 0 && parsed <= 100000)
			config.cases = (unsigned int)parsed;
	}
	value = getenv("IIP_FUZZ_FAILURE_PREFIX");
	if (value && *value)
		config.failure_prefix = value;
	return config;
}

static void fuzz_mutate_packet(void *pkt, void *opaque, uint64_t *random_state)
{
	uint8_t *data = iip_ops_pkt_get_data(pkt, opaque);
	uint16_t len = iip_ops_pkt_get_len(pkt, opaque);
	unsigned int mutations = 1U + (unsigned int)(fuzz_random(random_state) % 8U);
	unsigned int i;

	for (i = 0; i < mutations && len; i++) {
		uint64_t random = fuzz_random(random_state);
		uint16_t offset = (uint16_t)(random % len);
		uint8_t operation = (uint8_t)((random >> 16) % 4U);
		if (operation == 0)
			data[offset] ^= (uint8_t)(1U << ((random >> 24) & 7U));
		else if (operation == 1)
			data[offset] = (uint8_t)(random >> 32);
		else if (operation == 2)
			data[offset] = 0;
		else
			data[offset] = 0xff;
	}

	/* Occasionally truncate at any byte boundary, including empty L3/L4. */
	if ((fuzz_random(random_state) & 3U) == 0 && len)
		iip_ops_pkt_set_len(pkt,
			(uint16_t)(fuzz_random(random_state) % len), opaque);
}

static int fuzz_repair_ip4_tcp_checksums(void *pkt, void *opaque)
{
	uint16_t frame_len = iip_ops_pkt_get_len(pkt, opaque);
	uint16_t l2_len = iip_ops_l2_hdr_len(pkt, opaque);
	struct iip_ip4_hdr *ip4;
	uint16_t ip_header_len;
	uint16_t ip_total_len;

	if (frame_len < l2_len + sizeof(*ip4))
		return 0;
	ip4 = (struct iip_ip4_hdr *)((uint8_t *)iip_ops_pkt_get_data(pkt,
				opaque) + l2_len);
	if ((ip4->vl >> 4) != 4)
		return 0;
	ip_header_len = (uint16_t)(ip4->vl & 0x0f) * 4;
	ip_total_len = ii_ntohs(ip4->len_be);
	if (ip_header_len < sizeof(*ip4) || ip_header_len > 60 ||
			ip_total_len < ip_header_len + sizeof(struct iip_tcp_hdr) ||
			ip_total_len > frame_len - l2_len || ip4->proto != 6)
		return 0;
	update_ip4_checksum(pkt);
	update_tcp_checksum(pkt);
	return 1;
}

static int fuzz_save_failure(const struct fuzz_config *config,
		uint64_t case_seed, unsigned int case_index, void *pkt, void *opaque)
{
	char packet_path[512], metadata_path[512];
	FILE *file;
	uint8_t *data = iip_ops_pkt_get_data(pkt, opaque);
	uint16_t len = iip_ops_pkt_get_len(pkt, opaque);

	if (snprintf(packet_path, sizeof(packet_path), "%s-%016llx-%u.bin",
			config->failure_prefix, (unsigned long long)case_seed,
			case_index) >= (int)sizeof(packet_path) ||
			snprintf(metadata_path, sizeof(metadata_path), "%s-%016llx-%u.txt",
			config->failure_prefix, (unsigned long long)case_seed,
			case_index) >= (int)sizeof(metadata_path))
		return 0;
	file = fopen(packet_path, "wb");
	if (!file)
		return 0;
	if (fwrite(data, 1, len, file) != len) {
		fclose(file);
		return 0;
	}
	fclose(file);
	file = fopen(metadata_path, "w");
	if (!file)
		return 0;
	fprintf(file, "seed=0x%016llx\ncase=%u\nlength=%u\npacket=%s\n",
		(unsigned long long)case_seed, case_index, len, packet_path);
	fclose(file);
	fprintf(stderr,
		"fuzz failure: seed=0x%016llx case=%u packet=%s metadata=%s\n",
		(unsigned long long)case_seed, case_index, packet_path, metadata_path);
	return 1;
}

static int reproducible_packet_fuzz_scenario(void)
{
	struct fuzz_config config = fuzz_config_get();
	uint64_t suite_state = config.seed;
	unsigned int i;

	for (i = 0; i < config.cases; i++) {
		struct fixture f;
		struct tcp_packet_spec spec;
		uint8_t payload[32];
		uint64_t case_seed = fuzz_random(&suite_state);
		uint64_t case_state = case_seed;
		void *pkt;
		pid_t child;
		unsigned int j;

		if (!fixture_init(&f))
			return 0;
		for (j = 0; j < sizeof(payload); j++)
			payload[j] = (uint8_t)j;
		fixture_incoming_spec(&f, &spec, 0, payload,
			(uint16_t)(fuzz_random(&case_state) % (sizeof(payload) + 1U)));
		pkt = build_tcp_packet(&spec, &f.state);
		fuzz_mutate_packet(pkt, &f.state, &case_state);
		/*
		 * Preserve malformed-checksum coverage, but repair checksums for
		 * alternating structurally valid cases so mutations can reach the
		 * TCP option parser and state machine.
		 */
		if (i & 1U)
			(void)fuzz_repair_ip4_tcp_checksums(pkt, &f.state);

		fflush(NULL);
		child = fork();
		assert(child >= 0);
		if (!child) {
			f.state.accept_arbitrary_payload = 1;
			fixture_deliver(&f, pkt);
			_exit(0);
		}
		if (!wait_test_child(child, 1000)) {
			fuzz_save_failure(&config, case_seed, i, pkt, &f.state);
			iip_ops_pkt_free(pkt, &f.state);
			return 0;
		}
		iip_ops_pkt_free(pkt, &f.state);
	}
	return 1;
}

static enum result test_reproducible_packet_fuzz(const char **why)
{
	struct fuzz_config config = fuzz_config_get();

	if (!reproducible_packet_fuzz_scenario()) {
		*why = "reproducible packet fuzzing found a crash, assertion, or hang";
		return RESULT_FAIL;
	}
	printf("fuzz: seed=0x%016llx cases=%u\n",
		(unsigned long long)config.seed, config.cases);
	return RESULT_PASS;
}

static enum result test_invalid_option_length(const char **why)
{
	(void)legacy_test_main();
	if (!legacy_malformed_tests_passed) {
		*why = "legacy malformed-option test failed";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}


/* IPv4 host and ICMP scenarios.
 * Included by main.c after its shared packet/backend helpers.
 */

/*
 * IPv4 host requirements
 *
 * These tests cover the IPv4 host input/output path exposed by iip.  Router
 * forwarding requirements are deliberately out of scope.
 */

static void build_fixture_input(struct fixture *f, struct tcp_packet_spec *spec,
		void **pkt)
{
	static const uint8_t payload[] = { 0 };

	fixture_incoming_spec(f, spec, 0, payload, sizeof(payload));
	*pkt = build_tcp_packet(spec, &f->state);
}

static enum result test_ip4_tx_basic_header(const char **why)
{
	struct fixture f;
	void *pkt;
	void *opaque = &f.state;
	uint16_t total_len;

	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 0, 0, 1)))
		return RESULT_FAIL;
	total_len = ii_ntohs(PB_IP4(pkt)->len_be);
	if ((PB_IP4(pkt)->vl >> 4) != 4 ||
			(PB_IP4(pkt)->vl & 0x0f) < 5 ||
			total_len != iip_ops_pkt_get_len(pkt, opaque) -
				iip_ops_l2_hdr_len(pkt, opaque) ||
			PB_IP4(pkt)->proto != 6 ||
			PB_IP4(pkt)->src_be != ii_htonl(f.conn->src_ip[0]) ||
			PB_IP4(pkt)->dst_be != ii_htonl(f.conn->dst_ip[0]) ||
			!ip4_checksum_valid(pkt)) {
		*why = "generated IPv4 header fields are inconsistent";
		iip_ops_pkt_free(pkt, opaque);
		return RESULT_FAIL;
	}
	iip_ops_pkt_free(pkt, opaque);
	return RESULT_PASS;
}

/*
 * RFC 6864 Section 4: a source MAY set any ID value in an atomic datagram
 * (DF=1, MF=0, offset=0), and receivers MUST ignore the ID of atomic
 * datagrams.  Setting DF on originated datagrams is not mandatory, so only
 * require a small segment to be sent unfragmented, and check that atomic
 * datagrams with repeated ID 0 are all accepted.
 */
static enum result test_ip4_tx_atomic_datagram(const char **why)
{
	static const uint8_t payload[2] = { 0, 1 };
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;
	void *opaque = &f.state;
	uint16_t fragment;
	unsigned int i;

	if (!fixture_init(&f) || !(pkt = fixture_packet(&f, 0, 0, 0)))
		return RESULT_FAIL;
	fragment = ii_ntohs(PB_IP4(pkt)->off_be);
	iip_ops_pkt_free(pkt, opaque);
	if ((fragment & 0x3fff) != 0) {
		*why = "a small segment was sent as a fragment (MF=1 or offset!=0)";
		return RESULT_FAIL;
	}

	if (!fixture_init(&f))
		return RESULT_FAIL;
	for (i = 0; i < sizeof(payload); i++) {
		fixture_incoming_spec(&f, &spec, i, &payload[i], 1);
		pkt = build_tcp_packet(&spec, &f.state);
		PB_IP4(pkt)->id_be = 0;
		PB_IP4(pkt)->off_be = ii_htons(0x4000);
		update_ip4_checksum(pkt);
		fixture_deliver(&f, pkt);
	}
	if (f.state.payload_byte_count != sizeof(payload)) {
		*why = "atomic datagrams that reuse ID 0 were not all accepted";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_ip4_rx_wrong_version(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->vl = (6U << 4) | 5U;
	update_ip4_checksum(pkt);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_short_base_header(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	iip_ops_pkt_set_len(pkt, 14 + sizeof(struct iip_ip4_hdr) - 1,
			&f.state);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_small_ihl(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->vl = (4U << 4) | 4U;
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_total_length_below_ihl(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->len_be = ii_htons(sizeof(struct iip_ip4_hdr) - 1);
	update_ip4_checksum(pkt);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_truncated_total_length(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->len_be =
		ii_htons(ii_ntohs(PB_IP4(pkt)->len_be) + 1);
	update_ip4_checksum(pkt);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_header_checksum(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->csum_be ^= ii_htons(1);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_reserved_flag(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->off_be = ii_htons(0x8000);
	update_ip4_checksum(pkt);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_other_destination(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->dst_be = ii_htonl(0xc0000263U);
	update_ip4_checksum(pkt);
	update_tcp_checksum(pkt);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 0 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_l2_padding(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;
	uint16_t original_len;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	original_len = iip_ops_pkt_get_len(pkt, &f.state);
	memset((uint8_t *)iip_ops_pkt_get_data(pkt, &f.state) + original_len,
			0xa5, 8);
	iip_ops_pkt_set_len(pkt, original_len + 8, &f.state);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 1 && f.conn->seq_next_expected == 1
		? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_ttl_zero(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->ttl = 0;
	update_ip4_checksum(pkt);
	fixture_deliver(&f, pkt);
	if (f.state.payload_chunk_count != 1) {
		*why = "locally-destined TTL zero datagram was discarded";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_ip4_rx_ttl_one(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	void *pkt;

	(void)why;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	build_fixture_input(&f, &spec, &pkt);
	PB_IP4(pkt)->ttl = 1;
	update_ip4_checksum(pkt);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 1 ? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_576_octets(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	uint8_t payload[536];
	void *pkt;
	unsigned int i;

	(void)why;
	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)i;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	pkt = build_tcp_packet(&spec, &f.state);
	fixture_deliver(&f, pkt);
	return f.state.payload_chunk_count == 1 && f.conn->seq_next_expected == 536
		? RESULT_PASS : RESULT_FAIL;
}

static enum result test_ip4_rx_unknown_option_requirement(const char **why)
{
	return test_unknown_ip_option(why);
}

static enum result test_ip4_rx_invalid_source_requirement(const char **why)
{
	return test_invalid_source_syn(why);
}

static enum result test_ip4_fragment_reassembly(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	uint8_t payload[16];
	void *datagram;
	void *fragments[2];
	uint16_t ip_header_len;
	uint16_t ip_payload_len;
	unsigned int i;

	(void)why;
	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)i;
	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	datagram = build_tcp_packet(&spec, &f.state);
	ip_header_len = (PB_IP4(datagram)->vl & 0x0f) * 4;
	ip_payload_len = ii_ntohs(PB_IP4(datagram)->len_be) -
		ip_header_len;
	assert(ip_payload_len > 24);

	/* Deliver the last fragment first to verify order-independent assembly. */
	fragments[0] = fixture_ip4_fragment(&f, datagram, 24,
			ip_payload_len - 24, 0);
	fragments[1] = fixture_ip4_fragment(&f, datagram, 0, 24, 1);
	iip_ops_pkt_free(datagram, &f.state);
	deliver(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]), fragments,
			ARRAY_LENGTH(fragments), &f.state);
	return f.state.payload_chunk_count == ARRAY_LENGTH(fragments) &&
		f.conn->seq_next_expected == sizeof(payload) &&
		f.state.next_payload == sizeof(payload) &&
		!test_fragments_pending(f.ws)
		? RESULT_PASS : RESULT_FAIL;
}

static int test_ip4_in_order_fragment_reassembly_scenario(void)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	uint8_t payload[16];
	void *datagram;
	void *fragments[2];
	uint16_t ip_header_len;
	uint16_t ip_payload_len;
	unsigned int i;
	int ok = 1;

	TEST_CONDITION(fixture_init(&f),
			"failed to initialize the IPv4 fragment fixture");
	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)i;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	datagram = build_tcp_packet(&spec, &f.state);
	ip_header_len = PB_IP4_HDR_LEN(datagram);
	ip_payload_len = PB_IP4_TOTAL_LEN(datagram) - ip_header_len;
	TEST_CONDITION(ip_payload_len > 24,
			"test datagram payload is too short to split: %u",
			ip_payload_len);

	/*
	 * Deliver fragments in their natural order.  The second fragment belongs
	 * after the existing tail and must be linked into the same reassembly
	 * chain, rather than being enqueued as another incomplete context.
	 */
	fragments[0] = fixture_ip4_fragment(&f, datagram, 0, 24, 1);
	fragments[1] = fixture_ip4_fragment(&f, datagram, 24,
			ip_payload_len - 24, 0);
	iip_ops_pkt_free(datagram, &f.state);
	deliver(f.ws, f.local_mac, ii_htonl(f.conn->src_ip[0]), fragments,
			ARRAY_LENGTH(fragments), &f.state);

	TEST_ACCUMULATE(ok,
			f.state.payload_chunk_count == ARRAY_LENGTH(fragments),
			"expected %zu reassembled payload chunks, got %u",
			ARRAY_LENGTH(fragments), f.state.payload_chunk_count);
	TEST_ACCUMULATE(ok, f.conn->seq_next_expected == sizeof(payload),
			"expected TCP next sequence %zu after reassembly, got %u",
			sizeof(payload), f.conn->seq_next_expected);
	TEST_ACCUMULATE(ok, f.state.next_payload == sizeof(payload),
			"expected %zu payload bytes after reassembly, got %u",
			sizeof(payload), f.state.next_payload);
	TEST_ACCUMULATE(ok, !test_fragments_pending(f.ws),
			"fragment queue still contains incomplete reassembly contexts");
	return ok;
}

static enum result test_ip4_in_order_fragment_reassembly(const char **why)
{
	pid_t child = fork();

	if (child < 0) {
		*why = "could not fork timeout-isolated fragment test";
		return RESULT_FAIL;
	}
	if (!child)
		_exit(test_ip4_in_order_fragment_reassembly_scenario()
				? EXIT_SUCCESS : EXIT_FAILURE);
	if (!wait_test_child(child, 250)) {
		*why = "in-order fragments were not reassembled";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

/*
 * Deliver only the first fragment (offset 0) of a two-fragment datagram.
 * The returned copy of the original IPv4 header and first 8 octets is what an
 * ICMP Time Exceeded message must quote.
 */
static int fixture_deliver_first_fragment_only(struct fixture *f,
		uint8_t quoted[sizeof(struct iip_ip4_hdr) + 4 + 8])
{
	struct tcp_packet_spec spec;
	uint8_t payload[16] = { 0 };
	void *datagram;
	void *fragment;

	fake_clock_set_ns(&f->state, 1000000000ULL);
	fixture_incoming_spec(f, &spec, 0, payload, sizeof(payload));
	/*
	 * A 24-byte header keeps this test independent of the base-header
	 * fragment-length validation covered by test_ip4_fragment_reassembly.
	 */
	spec.ip_options[0] = 1; /* NOP */
	spec.ip_options[1] = 0; /* EOL */
	spec.ip_options_len = 4;
	datagram = build_tcp_packet(&spec, &f->state);
	fragment = fixture_ip4_fragment(f, datagram, 0, 24, 1);
	iip_ops_pkt_free(datagram, &f->state);
	memcpy(quoted, PB_IP4(fragment), sizeof(struct iip_ip4_hdr) + 4 + 8);
	fixture_deliver(f, fragment);
	return test_fragments_pending(f->ws);
}

/*
 * RFC 1122 Section 3.3.2: a reassembly timeout is mandatory, and a fixed
 * value between 60 and 120 seconds is recommended.  RFC 791's 15-second
 * example is not a requirement, so no lower bound is enforced.
 */
static enum result test_ip4_reassembly_timeout(const char **why)
{
	struct fixture f;
	uint8_t quoted[sizeof(struct iip_ip4_hdr) + 4 + 8];

	if (!fixture_init(&f))
		return RESULT_FAIL;
	if (!fixture_deliver_first_fragment_only(&f, quoted)) {
		*why = "the first fragment did not start a reassembly";
		return RESULT_FAIL;
	}
	fake_clock_advance_sec(&f.state, 121);
	fixture_run_timers(&f);
	if (!test_fragments_pending(f.ws))
		return RESULT_PASS;
	fake_clock_advance_sec(&f.state, 3600);
	fixture_run_timers(&f);
	if (!test_fragments_pending(f.ws)) {
		*why = "incomplete reassembly outlived the recommended 120 seconds";
		return RESULT_TODO;
	}
	*why = "incomplete reassembly was never discarded";
	return RESULT_FAIL;
}

/*
 * RFC 1122 Section 3.3.2: when the reassembly timer expires after fragment
 * zero has been received, an ICMP Time Exceeded (type 11, code 1) is sent to
 * the source.  The datagram here is unicast, so no ICMP error restriction
 * applies.  The message must quote the IPv4 header and the first 8 octets.
 */
static enum result test_ip4_reassembly_timeout_icmp(const char **why)
{
	struct fixture f;
	uint8_t quoted[sizeof(struct iip_ip4_hdr) + 4 + 8];
	void *reply;
	struct iip_icmp_hdr *icmp;
	uint16_t quoted_len;
	unsigned int waited;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	if (!fixture_deliver_first_fragment_only(&f, quoted)) {
		*why = "the first fragment did not start a reassembly";
		return RESULT_FAIL;
	}
	free_output(&f.state);
	for (waited = 0; waited < 3600 && test_fragments_pending(f.ws); waited += 10) {
		fake_clock_advance_sec(&f.state, 10);
		fixture_run_timers(&f);
	}
	if (test_fragments_pending(f.ws)) {
		*why = "incomplete reassembly was never discarded";
		return RESULT_FAIL;
	}
	if (output_count_ethertype(&f.state, 0x0800) != 1) {
		*why = "reassembly timeout did not produce one ICMP Time Exceeded";
		return RESULT_FAIL;
	}
	reply = output_nth_ethertype(&f.state, 0x0800, 0);
	icmp = PB_ICMP(reply);
	if (PB_IP4(reply)->proto != 1 ||
			PB_IP4(reply)->src_be != ii_htonl(f.conn->src_ip[0]) ||
			PB_IP4(reply)->dst_be != ii_htonl(f.conn->dst_ip[0]) ||
			!ip4_checksum_valid(reply)) {
		*why = "ICMP Time Exceeded has an invalid IPv4 envelope";
		return RESULT_FAIL;
	}
	if (icmp->type != 11 || icmp->code != 1 || !icmp_checksum_valid(reply)) {
		*why = "ICMP Time Exceeded type, code, or checksum is invalid";
		return RESULT_FAIL;
	}
	quoted_len = PB_IP4_TOTAL_LEN(reply) - PB_IP4_HDR_LEN(reply) - sizeof(*icmp);
	if (quoted_len < sizeof(quoted) ||
			memcmp(PB_ICMP_DATA(reply), quoted, sizeof(quoted))) {
		*why = "ICMP Time Exceeded does not quote the IPv4 header and 8 octets";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static void *fixture_icmp_echo_packet(struct fixture *f, uint8_t type,
		uint16_t identifier, uint16_t sequence, const uint8_t *data,
		uint16_t data_len)
{
	void *opaque = &f->state;
	void *pkt = iip_ops_pkt_alloc(opaque);
	struct iip_ip4_hdr *ip4;
	struct iip_icmp_hdr *icmp;
	const uint16_t icmp_len = sizeof(*icmp) + data_len;
	const uint16_t packet_len = 14 + sizeof(*ip4) + icmp_len;

	assert(pkt);
	memset(iip_ops_pkt_get_data(pkt, opaque), 0, packet_len);
	iip_ops_pkt_set_len(pkt, packet_len, opaque);
	iip_ops_l2_hdr_craft(pkt, f->peer_mac, f->local_mac,
			ii_htons(0x0800), opaque);
	ip4 = PB_IP4(pkt);
	ip4->vl = (4U << 4) | (sizeof(*ip4) / 4);
	ip4->len_be = ii_htons(sizeof(*ip4) + icmp_len);
	ip4->ttl = 64;
	ip4->proto = 1;
	ip4->src_be = ii_htonl(f->conn->dst_ip[0]);
	ip4->dst_be = ii_htonl(f->conn->src_ip[0]);
	icmp = PB_ICMP(pkt);
	icmp->type = type;
	icmp->code = 0;
	icmp->rest[0] = (uint8_t)(identifier >> 8);
	icmp->rest[1] = (uint8_t)identifier;
	icmp->rest[2] = (uint8_t)(sequence >> 8);
	icmp->rest[3] = (uint8_t)sequence;
	if (data_len)
		memcpy(PB_ICMP_DATA(pkt), data, data_len);
	update_ip4_checksum(pkt);
	update_icmp_checksum(pkt);
	return pkt;
}

static int icmp_echo_case(uint16_t identifier, uint16_t sequence,
		uint16_t data_len, const char **why)
{
	struct fixture f;
	uint8_t data[64];
	void *reply;
	struct iip_icmp_hdr *icmp;
	uint16_t i;

	assert(data_len <= sizeof(data));
	for (i = 0; i < data_len; i++)
		data[i] = (uint8_t)(0xa0 + i);
	if (!fixture_init(&f))
		return 0;
	fixture_deliver(&f, fixture_icmp_echo_packet(&f, 8, identifier,
			sequence, data, data_len));
	if (output_count_ethertype(&f.state, 0x0800) != 1) {
		*why = "a unicast Echo Request did not produce exactly one IPv4 reply";
		return 0;
	}
	reply = output_nth_ethertype(&f.state, 0x0800, 0);
	icmp = PB_ICMP(reply);
	if (PB_IP4(reply)->proto != 1 || !ip4_checksum_valid(reply) ||
			PB_IP4(reply)->dst_be != ii_htonl(f.conn->dst_ip[0])) {
		*why = "Echo Reply has an invalid IPv4 envelope";
		return 0;
	}
	/* RFC 1122 Section 3.2.2.6: the reply source is the request's
	 * specific destination address. */
	if (PB_IP4(reply)->src_be != ii_htonl(f.conn->src_ip[0])) {
		*why = "Echo Reply source is not the request destination address";
		return 0;
	}
	if (icmp->type != 0 || icmp->code != 0) {
		*why = "Echo Reply type or code is not 0";
		return 0;
	}
	if (icmp->rest[0] != (uint8_t)(identifier >> 8) ||
			icmp->rest[1] != (uint8_t)identifier ||
			icmp->rest[2] != (uint8_t)(sequence >> 8) ||
			icmp->rest[3] != (uint8_t)sequence) {
		*why = "Echo Reply did not return the identifier and sequence number";
		return 0;
	}
	if ((size_t)(PB_IP4_TOTAL_LEN(reply) - PB_IP4_HDR_LEN(reply)) !=
			sizeof(*icmp) + data_len ||
			(data_len && memcmp(PB_ICMP_DATA(reply), data, data_len))) {
		*why = "Echo Reply did not return the request data unchanged";
		return 0;
	}
	/* The checksum covers the whole ICMP message; an odd length is padded
	 * with a zero octet for the computation only. */
	if (!icmp_checksum_valid(reply)) {
		*why = "Echo Reply has an invalid ICMP checksum";
		return 0;
	}
	return 1;
}

/* RFC 1122 Section 3.2.2.6 and RFC 792: every host MUST implement an
 * Echo server.  Cover an empty, odd-length, and even-length payload, a zero
 * identifier, and a sequence number at the wrap boundary. */
static enum result test_icmp_echo_server(const char **why)
{
	if (!icmp_echo_case(0x1234, 1, 16, why) ||
			!icmp_echo_case(0, 0xffff, 0, why) ||
			!icmp_echo_case(0xbeef, 0, 7, why))
		return RESULT_FAIL;
	return RESULT_PASS;
}

/* An Echo Request with a bad ICMP checksum must be discarded, and an Echo
 * Reply must never trigger another reply. */
static enum result test_icmp_echo_discard(const char **why)
{
	static const uint8_t data[4] = { 1, 2, 3, 4 };
	struct fixture f;
	void *pkt;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	pkt = fixture_icmp_echo_packet(&f, 8, 1, 1, data, sizeof(data));
	PB_ICMP(pkt)->csum_be ^= ii_htons(1);
	fixture_deliver(&f, pkt);
	if (output_count_ethertype(&f.state, 0x0800) != 0) {
		*why = "an Echo Request with a bad checksum was answered";
		return RESULT_FAIL;
	}
	fixture_deliver(&f, fixture_icmp_echo_packet(&f, 0, 1, 1, data,
			sizeof(data)));
	if (output_count_ethertype(&f.state, 0x0800) != 0) {
		*why = "an Echo Reply triggered an IPv4 response";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}

static enum result test_ip4_malformed_option_error(const char **why)
{
	struct fixture f;
	struct tcp_packet_spec spec;
	const uint8_t payload[] = { 0 };
	void *input;
	void *reply;
	struct iip_ip4_hdr *reply_ip4;
	struct iip_icmp_hdr *icmp;
	uint8_t quoted[sizeof(struct iip_ip4_hdr) + 4 + 8];
	uint16_t reply_ip_header_len;
	uint16_t reply_total_len;
	uint16_t quoted_len;

	if (!fixture_init(&f))
		return RESULT_FAIL;
	fixture_incoming_spec(&f, &spec, 0, payload, sizeof(payload));
	/*
	 * The option area is four octets, but this unknown TLV claims five.
	 * The ICMP pointer must identify its invalid Length octet.
	 */
	spec.ip_options[0] = 0x9e;
	spec.ip_options[1] = 5;
	spec.ip_options_len = 4;
	input = build_tcp_packet(&spec, &f.state);
	memcpy(quoted, PB_IP4(input), sizeof(quoted));
	fixture_deliver(&f, input);

	if (f.state.payload_chunk_count != 0) {
		*why = "malformed IPv4 option was delivered to TCP";
		return RESULT_FAIL;
	}
	/*
	 * Discarding the datagram is mandatory; generating Parameter Problem
	 * is a SHOULD (RFC 1122 Section 3.2.2.5).  Report a missing message as
	 * TODO, but validate any message that is sent.
	 */
	if (output_count_ethertype(&f.state, 0x0800) == 0) {
		*why = "malformed IPv4 option was discarded without ICMP Parameter Problem (SHOULD)";
		return RESULT_TODO;
	}
	if (output_count_ethertype(&f.state, 0x0800) != 1) {
		*why = "malformed IPv4 option produced more than one IPv4 datagram";
		return RESULT_FAIL;
	}
	reply = output_nth_ethertype(&f.state, 0x0800, 0);
	reply_ip4 = PB_IP4(reply);
	if (reply_ip4->proto != 1 ||
			reply_ip4->src_be != ii_htonl(f.conn->src_ip[0]) ||
			reply_ip4->dst_be != ii_htonl(f.conn->dst_ip[0])) {
		*why = "ICMP Parameter Problem has an invalid IPv4 envelope";
		return RESULT_FAIL;
	}
	if (!ip4_checksum_valid(reply)) {
		*why = "ICMP Parameter Problem has an invalid IPv4 checksum";
		return RESULT_FAIL;
	}
	icmp = PB_ICMP(reply);
	if (icmp->type != 12 || icmp->code != 0 || icmp->rest[0] != 21 ||
			icmp->rest[1] || icmp->rest[2] || icmp->rest[3]) {
		*why = "ICMP Parameter Problem type, code, or pointer is invalid";
		return RESULT_FAIL;
	}
	if (!icmp_checksum_valid(reply)) {
		*why = "ICMP Parameter Problem has an invalid ICMP checksum";
		return RESULT_FAIL;
	}
	reply_ip_header_len = (uint16_t)(reply_ip4->vl & 0x0f) << 2;
	reply_total_len = ii_ntohs(reply_ip4->len_be);
	if (reply_total_len < reply_ip_header_len + sizeof(*icmp)) {
		*why = "ICMP Parameter Problem is truncated before its quotation";
		return RESULT_FAIL;
	}
	quoted_len = reply_total_len - reply_ip_header_len - sizeof(*icmp);
	if (quoted_len < sizeof(quoted) ||
			memcmp(PB_ICMP_DATA(reply), quoted, sizeof(quoted))) {
		*why = "ICMP Parameter Problem does not quote the IPv4 header and 8 octets";
		return RESULT_FAIL;
	}
	return RESULT_PASS;
}


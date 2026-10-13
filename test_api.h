/* Test-side helpers translate pool IDs to pointers for readable assertions. */
#define TEST_IP4_TTL 64
static uint16_t test_api_run(struct iip_workspace *, uint8_t *, uint32_t, void **, uint16_t, uint32_t *, void *);
static uint16_t test_api_connect(struct iip_workspace *, uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t, uint16_t, void *);
static uint16_t test_api_send(struct iip_workspace *, struct ii_tcp_conn *, void *, uint8_t, void *);
static uint16_t test_api_close(struct iip_workspace *, struct ii_tcp_conn *, void *);
static int test_api_consumed(struct iip_workspace *, struct ii_tcp_conn *, uint32_t, void *);
static void test_api_conn_init(struct iip_workspace *, struct ii_tcp_conn *, uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t, uint16_t, uint8_t, void *);
static void test_api_push(struct iip_workspace *, struct ii_tcp_conn *, void *, uint8_t, uint8_t, uint8_t, uint8_t, uint16_t, uint8_t *, uint8_t, void *);
static struct ii_pb *test_ring_end(struct iip_workspace *, struct ii_pb__ring *, unsigned int);
static void test_ring_remove(struct iip_workspace *, struct ii_pb__ring *, struct ii_pb *);
static void test_free_pb(struct iip_workspace *, struct ii_pb *, void *);
static void test_workspace_init(struct iip_workspace *);
static uint16_t test_api_fast_open(struct iip_workspace *, uint8_t *, uint32_t, uint16_t, uint8_t *, uint32_t, uint16_t, void *, uint8_t *, uint8_t, void *);
static uint16_t test_netcsum16(uint8_t **, uint16_t *, uint16_t, uint16_t);

static void *test_emit_queued(struct iip_workspace *, struct ii_tcp_conn *, struct ii_pb *, void *);
static unsigned int test_fragments_pending(struct iip_workspace *);
static uint16_t test_compute_tcp_window(uint32_t win, uint8_t scale)
{
	return ii_htons(ii_tcp_compute_win(win, scale));
}
static void test_set_keepalive(struct iip_workspace *w, struct ii_tcp_conn *conn,
		uint32_t interval_ms, void *opaque)
{
	conn->keepalive_interval_ms = interval_ms;
	if (interval_ms) conn->flags |= II_TCP_CONN_FLAGS_KEEPALIVE_ENABLED;
	else conn->flags &= ~II_TCP_CONN_FLAGS_KEEPALIVE_ENABLED;
	(void)w; (void)opaque;
}
static void test_set_retrans_r2(struct iip_workspace *w, struct ii_tcp_conn *conn,
		uint8_t limit, void *opaque)
{
	conn->retrans_r2 = limit;
	(void)w; (void)opaque;
}
static void test_set_diffserv(struct iip_workspace *w, struct ii_tcp_conn *conn,
		uint8_t diffserv, void *opaque)
{
	conn->diffserv = diffserv;
	(void)w; (void)opaque;
}
static int test_api_arp_request(struct iip_workspace *, uint8_t *, uint32_t, uint32_t, void *);

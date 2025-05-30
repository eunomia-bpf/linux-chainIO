/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <liburing.h>

#define PAGE_SIZE (4096)
#define AREA_SIZE (8192 * PAGE_SIZE)
#define SEND_SIZE (512 * 4096)
#define min(a, b) \
	({ \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a < _b ? _a : _b; \
	})
#define min_t(t, a, b) \
	({ \
		t _ta = (a); \
		t _tb = (b); \
		min(_ta, _tb); \
	})

static int cfg_family = PF_UNSPEC;
static int cfg_server = 0;
static int cfg_client = 0;
static int cfg_port = 8000;
static int cfg_payload_len;
static const char *cfg_ifname = NULL;
static int cfg_queue_id = -1;

static socklen_t cfg_alen;
static struct sockaddr_storage cfg_addr;

static char payload[SEND_SIZE] __attribute__((aligned(4096)));
static void *area_ptr = NULL;
static void *ring_ptr = NULL;
static size_t ring_size = 0;
static struct io_uring_zcrx_rq rq_ring;
static unsigned long area_token;
static int connfd = 0;
static bool stop = false;
static size_t received = 0;

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static void setup_zcrx(struct io_uring *ring)
{
	unsigned int ifindex;
	unsigned int rq_entries = 4096;
	int ret;

	ifindex = if_nametoindex(cfg_ifname);
	if (!ifindex)
		error(1, 0, "bad interface name: %s", cfg_ifname);

	area_ptr = mmap(NULL,
			AREA_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			0,
			0);
	if (area_ptr == MAP_FAILED)
		error(1, 0, "mmap(): zero copy area");

	ring_size = rq_entries * sizeof(struct io_uring_zcrx_rqe);
	ring_size += sizeof(io_uring);
	ring_size = (ring_size + 4095) & ~4095;
	ring_ptr = mmap(NULL,
			ring_size,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			0,
			0);

	struct io_uring_region_desc region_reg = {
		.size = ring_size,
		.user_addr = (__u64)(unsigned long)ring_ptr,
		.flags = IORING_MEM_REGION_TYPE_USER,
	};

	struct io_uring_zcrx_area_reg area_reg = {
		.addr = (__u64)(unsigned long)area_ptr,
		.len = AREA_SIZE,
		.flags = 0,
	};

	struct io_uring_zcrx_ifq_reg reg = {
		.if_idx = ifindex,
		.if_rxq = cfg_queue_id,
		.rq_entries = rq_entries,
		.area_ptr = (__u64)(unsigned long)&area_reg,
		.region_ptr = (__u64)(unsigned long)&region_reg,
	};

	ret = io_uring_register_ifq(ring, &reg);
	if (ret)
		error(1, 0, "io_uring_register_ifq(): %d", ret);

	rq_ring.khead = (unsigned int*)((char*)ring_ptr + reg.offsets.head);
	rq_ring.ktail = (unsigned int*)((char*)ring_ptr + reg.offsets.tail);
	rq_ring.rqes = (struct io_uring_zcrx_rqe*)((char*)ring_ptr + reg.offsets.rqes);
	rq_ring.rq_tail = 0;
	rq_ring.ring_entries = reg.rq_entries;

	area_token = area_reg.rq_area_token;
}

static void add_accept(struct io_uring *ring, int sockfd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);

	io_uring_prep_accept(sqe, sockfd, NULL, NULL, 0);
	sqe->user_data = 1;
}

static void add_recvzc(struct io_uring *ring, int sockfd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);

	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, sockfd, NULL, 0, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;
	sqe->user_data = 2;
}

static void process_accept(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	if (cqe->res < 0)
		error(1, 0, "accept()");
	if (connfd)
		error(1, 0, "Unexpected second connection");

	connfd = cqe->res;
	add_recvzc(ring, connfd);
}

static void process_recvzc(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	unsigned rq_mask = rq_ring.ring_entries - 1;
	struct io_uring_zcrx_cqe *rcqe;
	struct io_uring_zcrx_rqe* rqe;
	struct io_uring_sqe *sqe;
	uint64_t mask;
	char *data;
	ssize_t n;
	int i;

	if (cqe->res == 0 && cqe->flags == 0) {
		stop = true;
		return;
	}

	if (cqe->res < 0)
		error(1, 0, "recvzc(): %d", cqe->res);

	if (!(cqe->flags & IORING_CQE_F_MORE))
		add_recvzc(ring, connfd);

	rcqe = (struct io_uring_zcrx_cqe*)(cqe + 1);

	n = cqe->res;
	mask = (1ULL << IORING_ZCRX_AREA_SHIFT) - 1;
	data = (char *)area_ptr + (rcqe->off & mask);

	for (i = 0; i < n; i++) {
		if (*(data + i) != payload[(received + i)])
			error(1, 0, "payload mismatch");
	}
	received += n;

	rqe = &rq_ring.rqes[(rq_ring.rq_tail & rq_mask)];
	rqe->off = (rcqe->off & IORING_ZCRX_AREA_MASK) | area_token;
	rqe->len = cqe->res;
	IO_URING_WRITE_ONCE(*rq_ring.ktail, ++rq_ring.rq_tail);
}

static void server_loop(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	unsigned int count = 0;
	unsigned int head;
	int i, ret;

	io_uring_submit_and_wait(ring, 1);

	io_uring_for_each_cqe(ring, head, cqe) {
		if (cqe->user_data == 1)
			process_accept(ring, cqe);
		else if (cqe->user_data == 2)
			process_recvzc(ring, cqe);
		else
			error(1, 0, "unknown cqe");
		count++;
	}
	io_uring_cq_advance(ring, count);
}

static void run_server()
{
	unsigned int flags = 0;
	struct io_uring ring;
	int fd, enable, ret;
	uint64_t tstop;

	fd = socket(cfg_family, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, 0, "socket()");

	enable = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	if (ret < 0)
		error(1, 0, "setsockopt(SO_REUSEADDR)");

	ret = bind(fd, (const struct sockaddr *)&cfg_addr, sizeof(cfg_addr));
	if (ret < 0)
		error(1, 0, "bind()");

	if (listen(fd, 1024) < 0)
		error(1, 0, "listen()");

	flags |= IORING_SETUP_COOP_TASKRUN;
	flags |= IORING_SETUP_SINGLE_ISSUER;
	flags |= IORING_SETUP_DEFER_TASKRUN;
	flags |= IORING_SETUP_SUBMIT_ALL;
	flags |= IORING_SETUP_CQE32;

	io_uring_queue_init(512, &ring, flags);

	setup_zcrx(&ring);

	add_accept(&ring, fd);

	tstop = gettimeofday_ms() + 5000;
	while (!stop && gettimeofday_ms() < tstop)
		server_loop(&ring);

	if (!stop)
		error(1, 0, "test failed\n");
}

static void run_client()
{
	ssize_t to_send = SEND_SIZE;
	ssize_t sent = 0;
	ssize_t chunk, res;
	int fd;

	fd = socket(cfg_family, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, 0, "socket()");

	if (connect(fd, (void *)&cfg_addr, cfg_alen))
		error(1, 0, "connect()");

	while (to_send) {
		void *src = &payload[sent];

		chunk = min_t(ssize_t, cfg_payload_len, to_send);
		res = send(fd, src, chunk, 0);
		if (res < 0)
			error(1, 0, "send(): %d", sent);
		sent += res;
		to_send -= res;
	}

	close(fd);
}

static void usage(const char *filepath)
{
	error(1, 0, "Usage: %s (-4|-6) (-s|-c) -h<server_ip> -p<port> "
		    "-l<payload_size> -i<ifname> -q<rxq_id>", filepath);
}

static void parse_opts(int argc, char **argv)
{
	const int max_payload_len = sizeof(payload) -
				    sizeof(struct ipv6hdr) -
				    sizeof(struct tcphdr) -
				    40 /* max tcp options */;
	struct sockaddr_in6 *addr6 = (void *) &cfg_addr;
	struct sockaddr_in *addr4 = (void *) &cfg_addr;
	char *addr = NULL;
	int c;

	if (argc <= 1)
		usage(argv[0]);
	cfg_payload_len = max_payload_len;

	while ((c = getopt(argc, argv, "46sch:p:l:i:q:")) != -1) {
		switch (c) {
		case '4':
			if (cfg_family != PF_UNSPEC)
				error(1, 0, "Pass one of -4 or -6");
			cfg_family = PF_INET;
			cfg_alen = sizeof(struct sockaddr_in);
			break;
		case '6':
			if (cfg_family != PF_UNSPEC)
				error(1, 0, "Pass one of -4 or -6");
			cfg_family = PF_INET6;
			cfg_alen = sizeof(struct sockaddr_in6);
			break;
		case 's':
			if (cfg_client)
				error(1, 0, "Pass one of -s or -c");
			cfg_server = 1;
			break;
		case 'c':
			if (cfg_server)
				error(1, 0, "Pass one of -s or -c");
			cfg_client = 1;
			break;
		case 'h':
			addr = optarg;
			break;
		case 'p':
			cfg_port = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			cfg_payload_len = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'q':
			cfg_queue_id = strtoul(optarg, NULL, 0);
			break;
		}
	}

	if (cfg_server && addr)
		error(1, 0, "Receiver cannot have -h specified");

	switch (cfg_family) {
	case PF_INET:
		memset(addr4, 0, sizeof(*addr4));
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(cfg_port);
		addr4->sin_addr.s_addr = htonl(INADDR_ANY);
		
		if (addr &&
		    inet_pton(AF_INET, addr, &(addr4->sin_addr)) != 1)
			error(1, 0, "ipv4 parse error: %s", addr);
		break;
	case PF_INET6:
		memset(addr6, 0, sizeof(*addr6));
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(cfg_port);
		addr6->sin6_addr = in6addr_any;

		if (addr &&
		    inet_pton(AF_INET6, addr, &(addr6->sin6_addr)) != 1)
			error(1, 0, "ipv6 parse error: %s", addr);
		break;
	default:
		error(1, 0, "illegal domain");
	}

	if (cfg_payload_len > max_payload_len)
		error(1, 0, "-l: payload exceeds max (%d)", max_payload_len);
}

int main(int argc, char **argv)
{
	const char *cfg_test = argv[argc - 1];
	int i;

	parse_opts(argc, argv);

	for (i = 0; i < SEND_SIZE; i++)
		payload[i] = 'a' + (i % 26);

	if (cfg_server)
		run_server();
	else if (cfg_client)
		run_client();

	return 0;
}

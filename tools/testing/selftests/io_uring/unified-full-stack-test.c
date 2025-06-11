// SPDX-License-Identifier: GPL-2.0
/*
 * Complete stack test: NVMe + NIC + AF_XDP + eBPF + io_uring unified interface
 * 
 * This demonstrates a complete zero-copy data path:
 * Network packets -> eBPF processing -> AF_XDP -> unified buffer -> NVMe storage
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include "../../../../include/uapi/linux/io_uring.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <net/if.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#define IORING_REGISTER_UNIFIED_IFQ	33
#define IORING_UNREGISTER_UNIFIED_IFQ	34

/* Network configuration */
#define DEFAULT_IFNAME "eth0"
#define RX_BATCH_SIZE 64
#define NUM_FRAMES 4096
#define FRAME_SIZE 2048

/* Storage configuration */
#define STORAGE_BLOCK_SIZE 4096
#define MAX_PENDING_IOS 256

/* eBPF program to filter and process packets */
static const char *xdp_prog_src = 
"#include <linux/bpf.h>\n"
"#include <linux/if_ether.h>\n"
"#include <linux/ip.h>\n"
"#include <linux/udp.h>\n"
"#include <bpf/bpf_helpers.h>\n"
"#include <bpf/bpf_endian.h>\n"
"\n"
"struct {\n"
"    __uint(type, BPF_MAP_TYPE_XSKMAP);\n"
"    __uint(max_entries, 64);\n"
"    __uint(key_size, sizeof(int));\n"
"    __uint(value_size, sizeof(int));\n"
"} xsks_map SEC(\".maps\");\n"
"\n"
"struct packet_info {\n"
"    __u32 src_ip;\n"
"    __u32 dst_ip;\n"
"    __u16 src_port;\n"
"    __u16 dst_port;\n"
"    __u32 payload_len;\n"
"    __u64 timestamp;\n"
"};\n"
"\n"
"struct {\n"
"    __uint(type, BPF_MAP_TYPE_RINGBUF);\n"
"    __uint(max_entries, 256 * 1024);\n"
"} events SEC(\".maps\");\n"
"\n"
"SEC(\"xdp\")\n"
"int xdp_prog(struct xdp_md *ctx)\n"
"{\n"
"    void *data_end = (void *)(long)ctx->data_end;\n"
"    void *data = (void *)(long)ctx->data;\n"
"    struct ethhdr *eth = data;\n"
"    struct iphdr *ip;\n"
"    struct udphdr *udp;\n"
"    struct packet_info *info;\n"
"    __u32 payload_len;\n"
"    \n"
"    /* Basic packet validation */\n"
"    if (data + sizeof(*eth) > data_end)\n"
"        return XDP_PASS;\n"
"    \n"
"    if (eth->h_proto != bpf_htons(ETH_P_IP))\n"
"        return XDP_PASS;\n"
"    \n"
"    ip = data + sizeof(*eth);\n"
"    if (data + sizeof(*eth) + sizeof(*ip) > data_end)\n"
"        return XDP_PASS;\n"
"    \n"
"    /* Only process UDP packets to specific port */\n"
"    if (ip->protocol != IPPROTO_UDP)\n"
"        return XDP_PASS;\n"
"    \n"
"    udp = (struct udphdr *)(ip + 1);\n"
"    if ((void *)(udp + 1) > data_end)\n"
"        return XDP_PASS;\n"
"    \n"
"    /* Filter for storage port (e.g., 9999) */\n"
"    if (udp->dest != bpf_htons(9999))\n"
"        return XDP_PASS;\n"
"    \n"
"    payload_len = bpf_ntohs(udp->len) - sizeof(*udp);\n"
"    \n"
"    /* Log packet info to ringbuf */\n"
"    info = bpf_ringbuf_reserve(&events, sizeof(*info), 0);\n"
"    if (info) {\n"
"        info->src_ip = ip->saddr;\n"
"        info->dst_ip = ip->daddr;\n"
"        info->src_port = udp->source;\n"
"        info->dst_port = udp->dest;\n"
"        info->payload_len = payload_len;\n"
"        info->timestamp = bpf_ktime_get_ns();\n"
"        bpf_ringbuf_submit(info, 0);\n"
"    }\n"
"    \n"
"    /* Redirect to AF_XDP socket for zero-copy processing */\n"
"    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);\n"
"}\n"
"\n"
"char _license[] SEC(\"license\") = \"GPL\";\n";

/* Unified interface structures */
struct io_unified_reg {
	__u64 region_ptr;
	__u64 nvme_dev_path;
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 buffer_entries;
	__u32 buffer_entry_size;
	__u32 flags;
	__u32 __resv[3];
	
	struct {
		__u64 sq_ring;
		__u64 cq_ring;
		__u64 sq_entries;
		__u64 cq_entries;
		__u64 buffers;
	} offsets;
};

struct io_unified_ring {
	__u32 producer;
	__u32 consumer;
	__u32 cached_producer;
	__u32 cached_consumer;
	__u32 flags;
	__u32 ring_entries;
	__u64 ring_mask;
	__u64 ring_size;
};
struct nvme_uring_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32   rsvd2;
};
struct io_unified_sqe {
	struct nvme_uring_cmd nvme_cmd;
	__u64 buf_offset;
	__u64 user_data;
	__u32 flags;
	__u32 __pad;
};

struct io_unified_cqe {
	__u64 user_data;
	__s32 result;
	__u32 status;
	__u64 dma_addr;
	__u32 len;
	__u32 flags;
};

/* Global state */
struct app_context {
	/* io_uring unified interface */
	int ring_fd;
	void *unified_region;
	size_t region_size;
	struct io_unified_ring *sq_ring;
	struct io_unified_ring *cq_ring;
	struct io_unified_sqe *sq_entries;
	struct io_unified_cqe *cq_entries;
	void *data_buffers;
	
	/* AF_XDP socket */
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	
	/* eBPF */
	struct bpf_object *bpf_obj;
	struct bpf_program *xdp_prog;
	int xdp_prog_fd;
	int xsks_map_fd;
	int events_map_fd;
	
	/* Network interface */
	char ifname[IFNAMSIZ];
	int ifindex;
	int queue_id;
	
	/* NVMe device */
	char nvme_dev[256];
	
	/* Runtime state */
	volatile int running;
	pthread_t processing_thread;
	pthread_t storage_thread;
	
	/* Statistics */
	__u64 packets_received;
	__u64 packets_stored;
	__u64 bytes_stored;
	__u64 storage_errors;
};

static struct app_context ctx = {0};

/* Packet metadata stored with each buffer */
struct packet_metadata {
	__u64 timestamp;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 payload_len;
	__u32 buffer_id;
};

static void handle_signal(int sig)
{
	ctx.running = 0;
	printf("\nShutting down...\n");
}

static int setup_rlimit(void)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &r);
}

static int compile_and_load_bpf(void)
{
	char bpf_log_buf[16384];
	int prog_fd, err;
	
	/* Create temporary file for BPF program */
	FILE *f = fopen("/tmp/xdp_prog.c", "w");
	if (!f) {
		perror("fopen");
		return -1;
	}
	
	fprintf(f, "%s", xdp_prog_src);
	fclose(f);
	
	/* Compile with clang */
	system("clang -O2 -target bpf -c /tmp/xdp_prog.c -o /tmp/xdp_prog.o");
	
	/* Load BPF object */
	ctx.bpf_obj = bpf_object__open("/tmp/xdp_prog.o");
	if (libbpf_get_error(ctx.bpf_obj)) {
		fprintf(stderr, "Failed to open BPF object\n");
		return -1;
	}
	
	err = bpf_object__load(ctx.bpf_obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		return -1;
	}
	
	/* Get program and maps */
	ctx.xdp_prog = bpf_object__find_program_by_name(ctx.bpf_obj, "xdp_prog");
	if (!ctx.xdp_prog) {
		fprintf(stderr, "Failed to find XDP program\n");
		return -1;
	}
	
	ctx.xdp_prog_fd = bpf_program__fd(ctx.xdp_prog);
	ctx.xsks_map_fd = bpf_object__find_map_fd_by_name(ctx.bpf_obj, "xsks_map");
	ctx.events_map_fd = bpf_object__find_map_fd_by_name(ctx.bpf_obj, "events");
	
	printf("BPF program loaded successfully\n");
	return 0;
}

static int setup_af_xdp(void)
{
	struct xsk_socket_config cfg;
	struct xsk_umem_config umem_cfg;
	void *umem_area;
	int ret;
	
	/* Get interface index */
	ctx.ifindex = if_nametoindex(ctx.ifname);
	if (!ctx.ifindex) {
		fprintf(stderr, "Invalid interface name: %s\n", ctx.ifname);
		return -1;
	}
	
	/* Allocate UMEM area (shared with unified region) */
	umem_area = ctx.data_buffers;
	
	/* Configure UMEM */
	memset(&umem_cfg, 0, sizeof(umem_cfg));
	umem_cfg.fill_size = NUM_FRAMES / 2;
	umem_cfg.comp_size = NUM_FRAMES / 2;
	umem_cfg.frame_size = FRAME_SIZE;
	umem_cfg.frame_headroom = 0;
	umem_cfg.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
	
	ret = xsk_umem__create(&ctx.umem, umem_area, NUM_FRAMES * FRAME_SIZE,
			       &ctx.fq, &ctx.cq, &umem_cfg);
	if (ret) {
		fprintf(stderr, "Failed to create UMEM: %d\n", ret);
		return ret;
	}
	
	/* Configure AF_XDP socket */
	memset(&cfg, 0, sizeof(cfg));
	cfg.rx_size = NUM_FRAMES / 2;
	cfg.tx_size = NUM_FRAMES / 2;
	cfg.bind_flags = XDP_USE_NEED_WAKEUP;
	cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
	
	ret = xsk_socket__create(&ctx.xsk, ctx.ifname, ctx.queue_id, ctx.umem,
				 &ctx.rx, &ctx.tx, &cfg);
	if (ret) {
		fprintf(stderr, "Failed to create AF_XDP socket: %d\n", ret);
		return ret;
	}
	
	/* Add socket to BPF map */
	int sock_fd = xsk_socket__fd(ctx.xsk);
	ret = bpf_map_update_elem(ctx.xsks_map_fd, &ctx.queue_id, &sock_fd, 0);
	if (ret) {
		fprintf(stderr, "Failed to insert socket into BPF map: %d\n", ret);
		return ret;
	}
	
	/* Attach XDP program */
	ret = bpf_xdp_attach(ctx.ifindex, ctx.xdp_prog_fd, XDP_FLAGS_DRV_MODE, NULL);
	if (ret) {
		fprintf(stderr, "Failed to attach XDP program: %d\n", ret);
		return ret;
	}
	
	printf("AF_XDP socket created on %s queue %d\n", ctx.ifname, ctx.queue_id);
	return 0;
}

static int setup_unified_interface(void)
{
	struct io_uring_params params;
	struct io_uring_region_desc region_desc;
	struct io_unified_reg reg;
	int ret;
	
	/* Create io_uring with required flags */
	memset(&params, 0, sizeof(params));
	params.flags = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32 | 
		       IORING_SETUP_SQE128;
	
	ctx.ring_fd = syscall(__NR_io_uring_setup, 256, &params);
	if (ctx.ring_fd < 0) {
		perror("io_uring_setup");
		return ctx.ring_fd;
	}
	
	/* Calculate region size */
	ctx.region_size = 
		2 * sizeof(struct io_unified_ring) +           /* SQ + CQ rings */
		256 * sizeof(struct io_unified_sqe) +          /* SQ entries */
		256 * sizeof(struct io_unified_cqe) +          /* CQ entries */
		NUM_FRAMES * FRAME_SIZE;                       /* Data buffers */
	
	/* Allocate unified region */
	ctx.unified_region = mmap(NULL, ctx.region_size, PROT_READ | PROT_WRITE,
				  MAP_ANONYMOUS | MAP_SHARED | MAP_HUGETLB, -1, 0);
	if (ctx.unified_region == MAP_FAILED) {
		/* Fallback without hugepages */
		ctx.unified_region = mmap(NULL, ctx.region_size, PROT_READ | PROT_WRITE,
					  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
		if (ctx.unified_region == MAP_FAILED) {
			perror("mmap");
			close(ctx.ring_fd);
			return -1;
		}
	}
	
	printf("Allocated %zu bytes for unified region at %p\n", 
	       ctx.region_size, ctx.unified_region);
	
	/* Set up region descriptor */
	memset(&region_desc, 0, sizeof(region_desc));
	region_desc.user_addr = (__u64)(uintptr_t)ctx.unified_region;
	region_desc.size = ctx.region_size;
	
	/* Set up registration */
	memset(&reg, 0, sizeof(reg));
	reg.region_ptr = (__u64)(uintptr_t)&region_desc;
	reg.nvme_dev_path = (__u64)(uintptr_t)ctx.nvme_dev;
	reg.sq_entries = 256;
	reg.cq_entries = 256;
	reg.buffer_entries = NUM_FRAMES;
	reg.buffer_entry_size = FRAME_SIZE;
	
	/* Register unified interface */
	ret = syscall(__NR_io_uring_register, ctx.ring_fd, IORING_REGISTER_UNIFIED_IFQ,
		      &reg, 1);
	if (ret < 0) {
		perror("io_uring_register unified");
		munmap(ctx.unified_region, ctx.region_size);
		close(ctx.ring_fd);
		return ret;
	}
	
	/* Map ring structures */
	ctx.sq_ring = (struct io_unified_ring *)((char *)ctx.unified_region + reg.offsets.sq_ring);
	ctx.cq_ring = (struct io_unified_ring *)((char *)ctx.unified_region + reg.offsets.cq_ring);
	ctx.sq_entries = (struct io_unified_sqe *)((char *)ctx.unified_region + reg.offsets.sq_entries);
	ctx.cq_entries = (struct io_unified_cqe *)((char *)ctx.unified_region + reg.offsets.cq_entries);
	ctx.data_buffers = (char *)ctx.unified_region + reg.offsets.buffers;
	
	printf("Unified interface registered successfully\n");
	printf("  SQ ring: %p (entries: %u)\n", ctx.sq_ring, ctx.sq_ring->ring_entries);
	printf("  CQ ring: %p (entries: %u)\n", ctx.cq_ring, ctx.cq_ring->ring_entries);
	printf("  Data buffers: %p\n", ctx.data_buffers);
	
	return 0;
}

static void submit_storage_write(void *data, size_t len, __u64 lba, __u64 user_data)
{
	struct io_unified_sqe *sqe;
	__u32 sq_tail;
	
	/* Check if SQ has space */
	sq_tail = ctx.sq_ring->producer;
	if (sq_tail - ctx.sq_ring->consumer >= ctx.sq_ring->ring_entries) {
		ctx.storage_errors++;
		return; /* Ring full */
	}
	
	/* Get SQ entry */
	sqe = &ctx.sq_entries[sq_tail & ctx.sq_ring->ring_mask];
	memset(sqe, 0, sizeof(*sqe));
	
	/* Fill NVMe write command */
	sqe->nvme_cmd.opcode = 0x01;  /* Write */
	sqe->nvme_cmd.nsid = 1;       /* Namespace 1 */
	sqe->nvme_cmd.addr = (__u64)(uintptr_t)data;
	sqe->nvme_cmd.data_len = len;
	sqe->nvme_cmd.cdw10 = (__u32)(lba & 0xFFFFFFFF);
	sqe->nvme_cmd.cdw11 = (__u32)(lba >> 32);
	sqe->nvme_cmd.cdw12 = (len / 512) - 1;  /* Number of blocks - 1 */
	
	sqe->buf_offset = (char *)data - (char *)ctx.data_buffers;
	sqe->user_data = user_data;
	
	/* Submit */
	ctx.sq_ring->producer = sq_tail + 1;
	__sync_synchronize();
}

static void process_completions(void)
{
	__u32 cq_head = ctx.cq_ring->consumer;
	
	while (ctx.cq_ring->producer != cq_head) {
		struct io_unified_cqe *cqe = &ctx.cq_entries[cq_head & ctx.cq_ring->ring_mask];
		
		if (cqe->status == 0) {
			/* Success */
			ctx.packets_stored++;
			ctx.bytes_stored += cqe->len;
		} else {
			/* Error */
			ctx.storage_errors++;
			printf("Storage error: status=0x%x, result=%d\n", 
			       cqe->status, cqe->result);
		}
		
		cq_head++;
	}
	
	ctx.cq_ring->consumer = cq_head;
	__sync_synchronize();
}

static void *storage_thread(void *arg)
{
	printf("Storage thread started\n");
	
	while (ctx.running) {
		process_completions();
		usleep(1000); /* 1ms */
	}
	
	return NULL;
}

static void *packet_processing_thread(void *arg)
{
	__u32 idx_rx = 0, idx_fq = 0;
	int ret;
	static __u64 next_lba = 0;
	
	printf("Packet processing thread started\n");
	
	/* Populate fill queue initially */
	ret = xsk_ring_prod__reserve(&ctx.fq, NUM_FRAMES / 2, &idx_fq);
	for (int i = 0; i < ret; i++) {
		*xsk_ring_prod__fill_addr(&ctx.fq, idx_fq++) = i * FRAME_SIZE;
	}
	xsk_ring_prod__submit(&ctx.fq, ret);
	
	while (ctx.running) {
		/* Check for received packets */
		ret = xsk_ring_cons__peek(&ctx.rx, RX_BATCH_SIZE, &idx_rx);
		if (ret > 0) {
			/* Process batch of packets */
			for (int i = 0; i < ret; i++) {
				__u64 addr = xsk_ring_cons__rx_desc(&ctx.rx, idx_rx)->addr;
				__u32 len = xsk_ring_cons__rx_desc(&ctx.rx, idx_rx)->len;
				
				void *pkt_data = (char *)ctx.data_buffers + addr;
				
				/* Extract packet information */
				struct ethhdr *eth = (struct ethhdr *)pkt_data;
				struct iphdr *ip = (struct iphdr *)(eth + 1);
				struct udphdr *udp = (struct udphdr *)(ip + 1);
				void *payload = (char *)(udp + 1);
				__u32 payload_len = len - sizeof(*eth) - sizeof(*ip) - sizeof(*udp);
				
				/* Create packet metadata */
				struct packet_metadata *meta = 
					(struct packet_metadata *)((char *)pkt_data + len);
				meta->timestamp = time(NULL);
				meta->src_ip = ip->saddr;
				meta->dst_ip = ip->daddr;
				meta->src_port = udp->source;
				meta->dst_port = udp->dest;
				meta->payload_len = payload_len;
				meta->buffer_id = addr / FRAME_SIZE;
				
				/* Align payload for storage */
				size_t storage_len = (payload_len + sizeof(*meta) + 511) & ~511; /* 512-byte align */
				
				/* Submit to NVMe storage */
				submit_storage_write(payload, storage_len, next_lba, 
						    ((__u64)meta->src_ip << 32) | meta->timestamp);
				
				next_lba += storage_len / 512;
				ctx.packets_received++;
				
				idx_rx++;
			}
			
			/* Release RX descriptors */
			xsk_ring_cons__release(&ctx.rx, ret);
			
			/* Refill fill queue */
			ret = xsk_ring_prod__reserve(&ctx.fq, ret, &idx_fq);
			for (int i = 0; i < ret; i++) {
				*xsk_ring_prod__fill_addr(&ctx.fq, idx_fq++) = 
					(idx_fq - 1) * FRAME_SIZE;
			}
			xsk_ring_prod__submit(&ctx.fq, ret);
		}
		
		/* Handle completion notifications if needed */
		if (xsk_ring_prod__needs_wakeup(&ctx.fq)) {
			recvfrom(xsk_socket__fd(ctx.xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
	}
	
	return NULL;
}

static void print_stats(void)
{
	static __u64 last_packets = 0, last_bytes = 0;
	__u64 pps = ctx.packets_received - last_packets;
	__u64 bps = ctx.bytes_stored - last_bytes;
	
	printf("\rStats: RX=%llu pps=%llu | Stored=%llu Bps=%llu | Errors=%llu",
	       ctx.packets_received, pps, ctx.packets_stored, bps, ctx.storage_errors);
	fflush(stdout);
	
	last_packets = ctx.packets_received;
	last_bytes = ctx.bytes_stored;
}

int main(int argc, char *argv[])
{
	int ret;
	
	/* Parse arguments */
	if (argc > 1) {
		strncpy(ctx.ifname, argv[1], IFNAMSIZ - 1);
	} else {
		strncpy(ctx.ifname, DEFAULT_IFNAME, IFNAMSIZ - 1);
	}
	
	if (argc > 2) {
		strncpy(ctx.nvme_dev, argv[2], sizeof(ctx.nvme_dev) - 1);
	} else {
		strncpy(ctx.nvme_dev, "/dev/nvme0n1", sizeof(ctx.nvme_dev) - 1);
	}
	
	ctx.queue_id = (argc > 3) ? atoi(argv[3]) : 0;
	
	printf("Full-stack test: %s (queue %d) -> %s\n", 
	       ctx.ifname, ctx.queue_id, ctx.nvme_dev);
	printf("Listening for UDP packets on port 9999\n");
	
	/* Set up signal handling */
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	ctx.running = 1;
	
	/* Setup */
	ret = setup_rlimit();
	if (ret) {
		fprintf(stderr, "Failed to setup rlimit: %d\n", ret);
		return 1;
	}
	
	ret = setup_unified_interface();
	if (ret) {
		fprintf(stderr, "Failed to setup unified interface: %d\n", ret);
		return 1;
	}
	
	ret = compile_and_load_bpf();
	if (ret) {
		fprintf(stderr, "Failed to load BPF program: %d\n", ret);
		goto cleanup;
	}
	
	ret = setup_af_xdp();
	if (ret) {
		fprintf(stderr, "Failed to setup AF_XDP: %d\n", ret);
		goto cleanup;
	}
	
	/* Start processing threads */
	ret = pthread_create(&ctx.storage_thread, NULL, storage_thread, NULL);
	if (ret) {
		fprintf(stderr, "Failed to create storage thread: %d\n", ret);
		goto cleanup;
	}
	
	ret = pthread_create(&ctx.processing_thread, NULL, packet_processing_thread, NULL);
	if (ret) {
		fprintf(stderr, "Failed to create processing thread: %d\n", ret);
		goto cleanup;
	}
	
	printf("System ready. Waiting for packets...\n");
	
	/* Main loop - print stats */
	while (ctx.running) {
		print_stats();
		sleep(1);
	}
	
	/* Cleanup */
	pthread_join(ctx.processing_thread, NULL);
	pthread_join(ctx.storage_thread, NULL);
	
cleanup:
	if (ctx.xsk) {
		xsk_socket__delete(ctx.xsk);
	}
	if (ctx.umem) {
		xsk_umem__delete(ctx.umem);
	}
	if (ctx.xdp_prog_fd > 0) {
		bpf_xdp_detach(ctx.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	}
	if (ctx.bpf_obj) {
		bpf_object__close(ctx.bpf_obj);
	}
	if (ctx.ring_fd > 0) {
		syscall(__NR_io_uring_register, ctx.ring_fd, IORING_UNREGISTER_UNIFIED_IFQ, NULL, 0);
		close(ctx.ring_fd);
	}
	if (ctx.unified_region) {
		munmap(ctx.unified_region, ctx.region_size);
	}
	
	printf("\nFinal stats: Received=%llu, Stored=%llu, Bytes=%llu, Errors=%llu\n",
	       ctx.packets_received, ctx.packets_stored, ctx.bytes_stored, ctx.storage_errors);
	
	return 0;
}
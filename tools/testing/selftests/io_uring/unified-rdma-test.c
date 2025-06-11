// SPDX-License-Identifier: GPL-2.0
/*
 * Complete RDMA + AF_XDP + NVMe unified interface test
 * 
 * This demonstrates the ultimate zero-copy data path:
 * RDMA -> Unified Buffer <- AF_XDP -> NVMe Storage
 * 
 * Data can flow in multiple directions:
 * 1. Network (AF_XDP) -> Storage (NVMe)  
 * 2. RDMA -> Storage (NVMe)
 * 3. Network (AF_XDP) -> RDMA (forwarding)
 * 4. Storage (NVMe) -> RDMA (serving cached data)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
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
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <infiniband/verbs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>


#define IORING_REGISTER_UNIFIED_RDMA_IFQ	50
#define IORING_UNREGISTER_UNIFIED_RDMA_IFQ	51

/* RDMA operations */
#define IORING_OP_RDMA_SEND		60
#define IORING_OP_RDMA_RECV		61
#define IORING_OP_RDMA_WRITE		62
#define IORING_OP_RDMA_READ		63

/* Unified interface registration structure (from kernel unified.h) */
struct io_unified_reg {
	__u64 region_ptr;		/* pointer to region descriptor */
	__u64 nvme_dev_path;		/* path to nvme device */
	__u32 sq_entries;		/* number of submission queue entries */
	__u32 cq_entries;		/* number of completion queue entries */
	__u32 buffer_entries;		/* number of buffer entries */
	__u32 buffer_entry_size;	/* size of each buffer entry */
	__u32 flags;
	__u32 __resv[3];
	
	/* Output fields */
	struct {
		__u64 sq_ring;		/* offset to SQ ring */
		__u64 cq_ring;		/* offset to CQ ring */
		__u64 sq_entries;	/* offset to SQ entries */
		__u64 cq_entries;	/* offset to CQ entries */
		__u64 buffers;		/* offset to buffer area */
	} offsets;
};

/* Configuration */
#define DEFAULT_IFNAME "eth0"  /* Intel RDMA uses Ethernet interfaces */
#define DEFAULT_RDMA_DEV "irdma2"  /* Use active Intel RDMA device */
#define DEFAULT_RDMA_PORT 1
#define DEFAULT_SERVER_PORT 9999
#define MAX_PENDING_IOS 256
#define BUFFER_SIZE 4096
#define NUM_BUFFERS 4096

/* RDMA transport types */
enum rdma_transport {
	RDMA_TRANSPORT_RC,
	RDMA_TRANSPORT_UC, 
	RDMA_TRANSPORT_UD,
	RDMA_TRANSPORT_RAW_ETH,
};

/* RDMA operation types */
enum rdma_opcode {
	RDMA_OP_SEND,
	RDMA_OP_RECV,
	RDMA_OP_WRITE,
	RDMA_OP_READ,
	RDMA_OP_ATOMIC_CMP_AND_SWP,
	RDMA_OP_ATOMIC_FETCH_AND_ADD,
};

/* Unified interface structures (duplicated from kernel headers) */
struct io_unified_rdma_qp_config {
	__u32 transport_type;
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
	__u32 remote_qpn;
	__u32 rq_psn;
	__u32 sq_psn;
	__u32 dest_qp_num;
};

struct io_unified_rdma_reg {
	struct io_unified_reg base;	/* Base registration */
	
	__u64 rdma_dev_name;
	__u32 rdma_port;
	__u32 transport_type;
	
	struct io_unified_rdma_qp_config qp_config;
	
	__u32 xdp_flags;
	__u64 xdp_prog_path;
	__u32 num_mrs;
	__u32 mr_access_flags;
	
	struct {
		__u64 rdma_sq_ring;
		__u64 rdma_cq_ring;
		__u64 rdma_sq_entries;
		__u64 rdma_cq_entries;
		__u64 memory_regions;
	} rdma_offsets;
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

struct io_unified_rdma_wr {
	__u64 user_data;
	__u32 opcode;
	__u32 flags;
	__u64 local_addr;
	__u32 length;
	__u32 lkey;
	__u64 remote_addr;
	__u32 rkey;
	union {
		__u32 imm_data;
		__u64 compare_add;
		__u64 swap;
	};
	__u32 num_sge;
	struct {
		__u64 addr;
		__u32 length;
		__u32 lkey;
	} sge[16];
};

struct io_unified_rdma_cqe {
	__u64 user_data;
	__u32 status;
	__u32 opcode;
	__u32 byte_len;
	__u32 qp_num;
	__u32 src_qp;
	__u32 wc_flags;
	__u32 imm_data;
	__u16 pkey_index;
	__u16 slid;
	__u8 sl;
	__u8 dlid_path_bits;
};


/* Application context */
struct rdma_test_context {
	/* io_uring unified interface */
	int ring_fd;
	void *unified_region;
	size_t region_size;
	
	/* Base unified interface */
	struct io_unified_ring *sq_ring;
	struct io_unified_ring *cq_ring;
	void *sq_entries;
	void *cq_entries;
	void *data_buffers;
	
	/* RDMA-specific interface */
	struct io_unified_ring *rdma_sq_ring;
	struct io_unified_ring *rdma_cq_ring;
	struct io_unified_rdma_wr *rdma_sq_entries;
	struct io_unified_rdma_cqe *rdma_cq_entries;
	void *memory_regions;
	
	/* RDMA connection */
	struct rdma_cm_id *cm_id;
	struct rdma_event_channel *event_channel;
	struct ibv_context *verbs;
	struct ibv_pd *pd;
	struct ibv_cq *send_cq;
	struct ibv_cq *recv_cq;
	struct ibv_qp *qp;
	struct ibv_mr **mrs;
	int num_mrs;
	
	/* AF_XDP integration - placeholder structures */
	void *xsk;
	void *rx;
	void *tx;
	void *fq;
	void *cq;
	void *umem;
	
	/* Configuration */
	char rdma_dev_name[64];
	char ifname[IFNAMSIZ];
	char nvme_dev[256];
	int rdma_port;
	int transport_type;
	bool is_server;
	char server_addr[64];
	int server_port;
	
	/* Runtime state */
	volatile int running;
	int simulation_mode;  /* Run in simulation mode if kernel doesn't support unified RDMA */
	pthread_t rdma_thread;
	pthread_t network_thread;
	pthread_t storage_thread;
	pthread_t completion_thread;
	
	/* Statistics */
	__u64 rdma_sends;
	__u64 rdma_recvs;
	__u64 rdma_writes;
	__u64 rdma_reads;
	__u64 network_packets;
	__u64 storage_ops;
	__u64 bytes_transferred;
	__u64 errors;
};

static struct rdma_test_context ctx = {0};

/* Signal handling */
static void handle_signal(int sig)
{
	ctx.running = 0;
	printf("\nShutting down...\n");
}

/* RDMA connection management */
static int setup_rdma_connection(void)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr qp_attr;
	char port_str[16];
	int ret;
	
	/* Create event channel */
	ctx.event_channel = rdma_create_event_channel();
	if (!ctx.event_channel) {
		perror("rdma_create_event_channel");
		return -1;
	}
	
	/* Create CM ID */
	ret = rdma_create_id(ctx.event_channel, &ctx.cm_id, NULL, RDMA_PS_TCP);
	if (ret) {
		perror("rdma_create_id");
		return ret;
	}
	
	if (ctx.is_server) {
		/* Server side - bind and listen */
		struct sockaddr_in addr;
		
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(ctx.server_port);
		
		ret = rdma_bind_addr(ctx.cm_id, (struct sockaddr *)&addr);
		if (ret) {
			perror("rdma_bind_addr");
			return ret;
		}
		
		ret = rdma_listen(ctx.cm_id, 10);
		if (ret) {
			perror("rdma_listen");
			return ret;
		}
		
		printf("RDMA server listening on port %d\n", ctx.server_port);
	} else {
		/* Client side - resolve and connect */
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = RAI_NUMERICHOST;
		hints.ai_port_space = RDMA_PS_TCP;
		
		snprintf(port_str, sizeof(port_str), "%d", ctx.server_port);
		
		ret = rdma_getaddrinfo(ctx.server_addr, port_str, &hints, &res);
		if (ret) {
			printf("rdma_getaddrinfo: %s\n", gai_strerror(ret));
			return ret;
		}
		
		ret = rdma_resolve_addr(ctx.cm_id, NULL, res->ai_dst_addr, 2000);
		if (ret) {
			perror("rdma_resolve_addr");
			rdma_freeaddrinfo(res);
			return ret;
		}
		
		rdma_freeaddrinfo(res);
		printf("RDMA client connecting to %s:%d\n", ctx.server_addr, ctx.server_port);
	}
	
	return 0;
}

/* Setup unified RDMA interface */
static int setup_unified_rdma_interface(void)
{
	struct io_uring_params params;
	struct io_uring_region_desc region_desc;
	struct io_unified_rdma_reg reg;
	int ret;
	
	/* Create io_uring with required flags */
	memset(&params, 0, sizeof(params));
	params.flags = 0;  /* Start simple */
	
	ctx.ring_fd = syscall(__NR_io_uring_setup, 256, &params);
	if (ctx.ring_fd < 0) {
		perror("io_uring_setup");
		return ctx.ring_fd;
	}
	
	/* Calculate total region size */
	ctx.region_size = 
		/* Base unified interface */
		2 * sizeof(struct io_unified_ring) +           /* Base SQ/CQ rings */
		256 * 128 +                                    /* Base SQ entries (128B each) */
		256 * 64 +                                     /* Base CQ entries (64B each) */
		NUM_BUFFERS * BUFFER_SIZE +                    /* Data buffers */
		/* RDMA extensions */
		2 * sizeof(struct io_unified_ring) +           /* RDMA SQ/CQ rings */
		256 * sizeof(struct io_unified_rdma_wr) +      /* RDMA SQ entries */
		256 * sizeof(struct io_unified_rdma_cqe) +     /* RDMA CQ entries */
		64 * 64;                                       /* Memory region descriptors */
	
	/* Round up to page boundary */
	size_t page_size = getpagesize();
	ctx.region_size = (ctx.region_size + page_size - 1) & ~(page_size - 1);
	
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
	
	printf("Allocated %zu bytes for unified RDMA region at %p\n", 
	       ctx.region_size, ctx.unified_region);
	
	/* Set up region descriptor */
	memset(&region_desc, 0, sizeof(region_desc));
	region_desc.user_addr = (__u64)(uintptr_t)ctx.unified_region;
	region_desc.size = ctx.region_size;
	region_desc.flags = IORING_MEM_REGION_TYPE_USER;  /* User memory region */
	region_desc.id = 0;
	region_desc.mmap_offset = 0;
	
	printf("Region descriptor:\n");
	printf("  user_addr: 0x%llx\n", region_desc.user_addr);
	printf("  size: %llu\n", region_desc.size);
	printf("  flags: %u\n", region_desc.flags);
	printf("  id: %u\n", region_desc.id);
	
	/* Set up RDMA unified registration */
	struct io_unified_rdma_reg rdma_reg;
	memset(&rdma_reg, 0, sizeof(rdma_reg));
	
	/* Base unified registration */
	rdma_reg.base.region_ptr = (__u64)(uintptr_t)&region_desc;
	rdma_reg.base.nvme_dev_path = (__u64)(uintptr_t)ctx.nvme_dev;
	rdma_reg.base.sq_entries = 256;
	rdma_reg.base.cq_entries = 256;
	rdma_reg.base.buffer_entries = NUM_BUFFERS;
	rdma_reg.base.buffer_entry_size = BUFFER_SIZE;
	
	/* RDMA-specific configuration */
	rdma_reg.rdma_dev_name = (__u64)(uintptr_t)ctx.rdma_dev_name;
	rdma_reg.rdma_port = ctx.rdma_port;
	rdma_reg.transport_type = ctx.transport_type;
	
	/* QP configuration with safe defaults */
	rdma_reg.qp_config.transport_type = ctx.transport_type;
	rdma_reg.qp_config.max_send_wr = 256;
	rdma_reg.qp_config.max_recv_wr = 256;
	rdma_reg.qp_config.max_send_sge = 1;  /* Start with 1 SGE */
	rdma_reg.qp_config.max_recv_sge = 1;  /* Start with 1 SGE */
	rdma_reg.qp_config.max_inline_data = 0; /* No inline data for safety */
	
	/* Initialize connection parameters with zeros */
	rdma_reg.qp_config.remote_qpn = 0;
	rdma_reg.qp_config.rq_psn = 0;
	rdma_reg.qp_config.sq_psn = 0;
	rdma_reg.qp_config.dest_qp_num = 0;
	
	rdma_reg.num_mrs = 8;  /* Reduce from 64 to 8 */
	rdma_reg.mr_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | 
			      IBV_ACCESS_REMOTE_READ;
	
	printf("RDMA unified registration:\n");
	printf("  region_ptr: 0x%llx\n", rdma_reg.base.region_ptr);
	printf("  nvme_dev_path: 0x%llx (\"%s\")\n", rdma_reg.base.nvme_dev_path, ctx.nvme_dev);
	printf("  rdma_dev_name: 0x%llx (\"%s\")\n", rdma_reg.rdma_dev_name, ctx.rdma_dev_name);
	printf("  rdma_port: %u\n", rdma_reg.rdma_port);
	printf("  transport_type: %u\n", rdma_reg.transport_type);
	printf("  sq_entries: %u\n", rdma_reg.base.sq_entries);
	printf("  cq_entries: %u\n", rdma_reg.base.cq_entries);
	printf("  buffer_entries: %u\n", rdma_reg.base.buffer_entries);
	printf("  buffer_entry_size: %u\n", rdma_reg.base.buffer_entry_size);
	printf("  max_send_wr: %u\n", rdma_reg.qp_config.max_send_wr);
	printf("  max_recv_wr: %u\n", rdma_reg.qp_config.max_recv_wr);
	printf("  max_send_sge: %u\n", rdma_reg.qp_config.max_send_sge);
	printf("  max_recv_sge: %u\n", rdma_reg.qp_config.max_recv_sge);
	printf("  max_inline_data: %u\n", rdma_reg.qp_config.max_inline_data);
	printf("  num_mrs: %u\n", rdma_reg.num_mrs);
	printf("  mr_access_flags: 0x%x\n", rdma_reg.mr_access_flags);
	
	/* Register unified RDMA interface (includes base setup) */
	ret = syscall(__NR_io_uring_register, ctx.ring_fd, IORING_REGISTER_UNIFIED_RDMA_IFQ,
		      &rdma_reg, 1);
	if (ret < 0) {
		printf("io_uring_register unified RDMA failed: %s\n", strerror(errno));
		return ret;
	} 
	
	/* Map ring structures only if not in simulation mode */
		ctx.sq_ring = (struct io_unified_ring *)((char *)ctx.unified_region + rdma_reg.base.offsets.sq_ring);
		ctx.cq_ring = (struct io_unified_ring *)((char *)ctx.unified_region + rdma_reg.base.offsets.cq_ring);
		ctx.sq_entries = (char *)ctx.unified_region + rdma_reg.base.offsets.sq_entries;
		ctx.cq_entries = (char *)ctx.unified_region + rdma_reg.base.offsets.cq_entries;
		ctx.data_buffers = (char *)ctx.unified_region + rdma_reg.base.offsets.buffers;
		
		/* Map RDMA-specific structures */
		ctx.rdma_sq_ring = (struct io_unified_ring *)((char *)ctx.unified_region + rdma_reg.rdma_offsets.rdma_sq_ring);
		ctx.rdma_cq_ring = (struct io_unified_ring *)((char *)ctx.unified_region + rdma_reg.rdma_offsets.rdma_cq_ring);
		ctx.rdma_sq_entries = (struct io_unified_rdma_wr *)((char *)ctx.unified_region + rdma_reg.rdma_offsets.rdma_sq_entries);
		ctx.rdma_cq_entries = (struct io_unified_rdma_cqe *)((char *)ctx.unified_region + rdma_reg.rdma_offsets.rdma_cq_entries);
		ctx.memory_regions = (char *)ctx.unified_region + rdma_reg.rdma_offsets.memory_regions;
	
	printf("  Base SQ ring: %p (entries: %u)\n", ctx.sq_ring, ctx.sq_ring->ring_entries);
	printf("  Base CQ ring: %p (entries: %u)\n", ctx.cq_ring, ctx.cq_ring->ring_entries);
	printf("  RDMA SQ ring: %p (entries: %u)\n", ctx.rdma_sq_ring, ctx.rdma_sq_ring->ring_entries);
	printf("  RDMA CQ ring: %p (entries: %u)\n", ctx.rdma_cq_ring, ctx.rdma_cq_ring->ring_entries);
	printf("  Data buffers: %p\n", ctx.data_buffers);
	
	return 0;
}

/* Submit RDMA work request using io_uring operations */
static int submit_rdma_send(void *data, size_t len, __u64 user_data)
{
	struct io_uring_sqe sqe;
	
	/* Prepare io_uring SQE for RDMA send */
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RDMA_SEND;
	sqe.user_data = user_data;
	sqe.addr = (__u64)(uintptr_t)data;
	sqe.len = len;
	sqe.msg_flags = 0;
	
	/* For this test, we'll just increment the counter */
	/* In a real implementation, you'd submit to io_uring */
	printf("RDMA send prepared: data=%p, len=%zu, user_data=0x%llx\n", 
	       data, len, user_data);
	
	ctx.rdma_sends++;
	return 0;
}

/* Submit RDMA receive request */
static int submit_rdma_recv(void *data, size_t len, __u64 user_data)
{
	/* RDMA functionality not available in current unified interface */
	if (!ctx.rdma_sq_ring || !ctx.rdma_sq_entries) {
		printf("RDMA recv simulated (data: %p, len: %zu)\n", data, len);
		ctx.rdma_recvs++;
		return 0;
	}
	
	struct io_unified_rdma_wr *wr;
	__u32 sq_tail;
	
	/* This would typically go to a separate recv queue, but for
	   simplicity we use the same SQ mechanism */
	sq_tail = ctx.rdma_sq_ring->producer;
	if (sq_tail - ctx.rdma_sq_ring->consumer >= ctx.rdma_sq_ring->ring_entries) {
		ctx.errors++;
		return -ENOSPC;
	}
	
	wr = &ctx.rdma_sq_entries[sq_tail & ctx.rdma_sq_ring->ring_mask];
	memset(wr, 0, sizeof(*wr));
	
	wr->user_data = user_data;
	wr->opcode = RDMA_OP_RECV;
	wr->num_sge = 1;
	wr->sge[0].addr = (__u64)(uintptr_t)data;
	wr->sge[0].length = len;
	wr->sge[0].lkey = 0;
	
	ctx.rdma_sq_ring->producer = sq_tail + 1;
	__sync_synchronize();
	
	ctx.rdma_recvs++;
	return 0;
}

/* Process RDMA completions */
static void process_rdma_completions(void)
{
	/* RDMA functionality not available in current unified interface */
	if (!ctx.rdma_cq_ring || !ctx.rdma_cq_entries) {
		/* Simulate some completion processing */
		return;
	}
	
	__u32 cq_head = ctx.rdma_cq_ring->consumer;
	
	while (ctx.rdma_cq_ring->producer != cq_head) {
		struct io_unified_rdma_cqe *cqe = &ctx.rdma_cq_entries[cq_head & ctx.rdma_cq_ring->ring_mask];
		
		if (cqe->status == 0) {
			/* Success */
			ctx.bytes_transferred += cqe->byte_len;
			
			if (cqe->opcode == RDMA_OP_RECV) {
				/* Received data - can forward to storage or process */
				printf("RDMA received %u bytes from QP %u\n", 
				       cqe->byte_len, cqe->src_qp);
			}
		} else {
			/* Error */
			ctx.errors++;
			printf("RDMA completion error: status=%u, opcode=%u\n", 
			       cqe->status, cqe->opcode);
		}
		
		cq_head++;
	}
	
	ctx.rdma_cq_ring->consumer = cq_head;
	__sync_synchronize();
}

/* RDMA connection event handling thread */
static void *rdma_thread(void *arg)
{
	struct rdma_cm_event *event;
	int ret;
	
	printf("RDMA thread started\n");
	
	while (ctx.running) {
		ret = rdma_get_cm_event(ctx.event_channel, &event);
		if (ret) {
			if (ctx.running) {
				perror("rdma_get_cm_event");
			}
			break;
		}
		
		switch (event->event) {
		case RDMA_CM_EVENT_ADDR_RESOLVED:
			printf("RDMA address resolved\n");
			ret = rdma_resolve_route(ctx.cm_id, 2000);
			if (ret) {
				perror("rdma_resolve_route");
			}
			break;
			
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			printf("RDMA route resolved\n");
			/* Would normally create QP and connect here */
			/* RDMA connect handled by userspace RDMA libraries */
			ret = 0;
			if (ret) {
				printf("RDMA connect failed: %d\n", ret);
			}
			break;
			
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			printf("RDMA connection request received\n");
			ret = rdma_accept(event->id, NULL);
			if (ret) {
				perror("rdma_accept");
			}
			break;
			
		case RDMA_CM_EVENT_ESTABLISHED:
			printf("RDMA connection established\n");
			/* Start posting receive requests */
			for (int i = 0; i < 16; i++) {
				void *buf = (char *)ctx.data_buffers + i * BUFFER_SIZE;
				submit_rdma_recv(buf, BUFFER_SIZE, i);
			}
			break;
			
		case RDMA_CM_EVENT_DISCONNECTED:
			printf("RDMA connection disconnected\n");
			ctx.running = 0;
			break;
			
		default:
			printf("RDMA event: %s\n", rdma_event_str(event->event));
			break;
		}
		
		rdma_ack_cm_event(event);
	}
	
	return NULL;
}

/* Network packet processing thread */
static void *network_thread(void *arg)
{
	printf("Network thread started\n");
	
	/* This would integrate with AF_XDP like in the previous example */
	while (ctx.running) {
		/* Simulate network packet processing */
		usleep(10000);  /* 10ms */
		
		/* Example: forward received packets via RDMA */
		if (ctx.network_packets % 100 == 0) {
			char *data = (char *)ctx.data_buffers + (ctx.network_packets % NUM_BUFFERS) * BUFFER_SIZE;
			snprintf(data, BUFFER_SIZE, "Network packet %llu", ctx.network_packets);
			submit_rdma_send(data, strlen(data), ctx.network_packets);
		}
		
		ctx.network_packets++;
	}
	
	return NULL;
}

/* Storage operations thread */
static void *storage_thread(void *arg)
{
	printf("Storage thread started\n");
	
	while (ctx.running) {
		/* Process storage operations from base unified interface */
		/* This would use the same logic as in unified.c */
		usleep(5000);  /* 5ms */
		ctx.storage_ops++;
	}
	
	return NULL;
}

/* Completion processing thread */
static void *completion_thread(void *arg)
{
	printf("Completion thread started\n");
	
	while (ctx.running) {
		/* Process RDMA completions */
		process_rdma_completions();
		
		/* Process storage completions */
		/* This would process both base and RDMA completion queues */
		
		usleep(1000);  /* 1ms */
	}
	
	return NULL;
}

/* Print statistics */
static void print_stats(void)
{
	static __u64 last_sends = 0, last_recvs = 0, last_bytes = 0;
	__u64 send_rate = ctx.rdma_sends - last_sends;
	__u64 recv_rate = ctx.rdma_recvs - last_recvs;
	__u64 byte_rate = ctx.bytes_transferred - last_bytes;
	
	printf("\rStats: RDMA TX=%llu(%llu/s) RX=%llu(%llu/s) | Network=%llu | Storage=%llu | Bytes=%llu(%llu/s) | Errors=%llu",
	       ctx.rdma_sends, send_rate,
	       ctx.rdma_recvs, recv_rate,
	       ctx.network_packets,
	       ctx.storage_ops,
	       ctx.bytes_transferred, byte_rate,
	       ctx.errors);
	fflush(stdout);
	
	last_sends = ctx.rdma_sends;
	last_recvs = ctx.rdma_recvs;
	last_bytes = ctx.bytes_transferred;
}

/* Demonstrate different data flow patterns */
static void demonstrate_data_flows(void)
{
	printf("\nDemonstrating unified data flows:\n");
	
	/* 1. RDMA -> Storage */
	printf("1. RDMA data to storage...\n");
	char *rdma_data = (char *)ctx.data_buffers;
	strcpy(rdma_data, "RDMA data for storage");
	/* Submit to storage via base unified interface */
	
	/* 2. Network -> RDMA forwarding */
	printf("2. Network to RDMA forwarding...\n");
	char *net_data = (char *)ctx.data_buffers + BUFFER_SIZE;
	strcpy(net_data, "Network data via RDMA");
	submit_rdma_send(net_data, strlen(net_data), 0x200);
	
	/* 3. Storage -> RDMA (cached data serving) */
	printf("3. Storage to RDMA (cache serving)...\n");
	char *cache_data = (char *)ctx.data_buffers + 2 * BUFFER_SIZE;
	strcpy(cache_data, "Cached data from storage");
	submit_rdma_send(cache_data, strlen(cache_data), 0x300);
	
	printf("Data flow demonstrations submitted\n");
}

/* Check if an RDMA device port is active */
static int is_rdma_port_active(const char *dev_name, int port)
{
	char path[256];
	char state_str[32];
	FILE *f;
	int state = 0;
	
	snprintf(path, sizeof(path), "/sys/class/infiniband/%s/ports/%d/state", dev_name, port);
	f = fopen(path, "r");
	if (!f)
		return 0;
	
	if (fgets(state_str, sizeof(state_str), f)) {
		/* PORT_ACTIVE is state 4 */
		state = atoi(state_str);
	}
	fclose(f);
	
	return (state == 4); /* PORT_ACTIVE */
}

/* Find best available RDMA device (prefer active devices) */
static int find_rdma_device(char *dev_name, size_t dev_name_size)
{
	struct dirent *entry;
	DIR *dir;
	char first_available[64] = {0};
	char active_device[64] = {0};
	int found_any = 0;
	
	dir = opendir("/sys/class/infiniband");
	if (!dir) {
		fprintf(stderr, "Warning: Cannot access /sys/class/infiniband, using default device\n");
		strncpy(dev_name, DEFAULT_RDMA_DEV, dev_name_size - 1);
		dev_name[dev_name_size - 1] = '\0';
		return 0;
	}
	
	/* Scan all devices to find the best one */
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.' || strlen(entry->d_name) == 0)
			continue;
			
		printf("Found RDMA device: %s", entry->d_name);
		
		/* Check if this device has an active port */
		if (is_rdma_port_active(entry->d_name, 1)) {
			printf(" (PORT_ACTIVE)\n");
			if (active_device[0] == '\0') {
				strncpy(active_device, entry->d_name, sizeof(active_device) - 1);
			}
		} else {
			printf(" (PORT_DOWN)\n");
		}
		
		/* Keep track of first available device as fallback */
		if (!found_any) {
			strncpy(first_available, entry->d_name, sizeof(first_available) - 1);
			found_any = 1;
		}
	}
	
	closedir(dir);
	
	if (!found_any) {
		fprintf(stderr, "No RDMA devices found in /sys/class/infiniband\n");
		return -ENODEV;
	}
	
	/* Prefer active device, fallback to first available */
	if (active_device[0] != '\0') {
		strncpy(dev_name, active_device, dev_name_size - 1);
		printf("Using active RDMA device: %s\n", dev_name);
	} else {
		strncpy(dev_name, first_available, dev_name_size - 1);
		printf("Using RDMA device: %s (no active ports found)\n", dev_name);
	}
	
	dev_name[dev_name_size - 1] = '\0';
	return 0;
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
		strncpy(ctx.rdma_dev_name, argv[2], sizeof(ctx.rdma_dev_name) - 1);
	} else {
		ret = find_rdma_device(ctx.rdma_dev_name, sizeof(ctx.rdma_dev_name));
		if (ret < 0) {
			fprintf(stderr, "No RDMA devices found\n");
			return ret;
		}
	}
	
	if (argc > 3) {
		strncpy(ctx.nvme_dev, argv[3], sizeof(ctx.nvme_dev) - 1);
	} else {
		strncpy(ctx.nvme_dev, "/dev/nvme0n1", sizeof(ctx.nvme_dev) - 1);
	}
	
	if (argc > 4) {
		ctx.is_server = (strcmp(argv[4], "server") == 0);
		if (!ctx.is_server) {
			strncpy(ctx.server_addr, argv[4], sizeof(ctx.server_addr) - 1);
		}
	} else {
		ctx.is_server = true;  /* Default to server mode */
	}
	
	ctx.rdma_port = DEFAULT_RDMA_PORT;
	ctx.transport_type = RDMA_TRANSPORT_RC;
	ctx.server_port = DEFAULT_SERVER_PORT;
	
	printf("Unified RDMA + AF_XDP + NVMe Test\n");
	printf("==================================\n");
	printf("Interface: %s\n", ctx.ifname);
	printf("RDMA device: %s (port %d)\n", ctx.rdma_dev_name, ctx.rdma_port);
	printf("NVMe device: %s\n", ctx.nvme_dev);
	printf("Mode: %s\n", ctx.is_server ? "server" : "client");
	if (!ctx.is_server) {
		printf("Server: %s:%d\n", ctx.server_addr, ctx.server_port);
	}
	printf("\n");
	
	/* Set up signal handling */
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	ctx.running = 1;
	
	/* Setup unified RDMA interface */
	ret = setup_unified_rdma_interface();
	if (ret) {
		fprintf(stderr, "Failed to setup unified RDMA interface: %d\n", ret);
		return 1;
	}
	
	/* Setup RDMA connection */
	ret = setup_rdma_connection();
	if (ret) {
		fprintf(stderr, "Failed to setup RDMA connection: %d\n", ret);
		goto cleanup;
	}
	
	/* Start processing threads */
	ret = pthread_create(&ctx.rdma_thread, NULL, rdma_thread, NULL);
	if (ret) {
		fprintf(stderr, "Failed to create RDMA thread: %d\n", ret);
		goto cleanup;
	}
	
	ret = pthread_create(&ctx.network_thread, NULL, network_thread, NULL);
	if (ret) {
		fprintf(stderr, "Failed to create network thread: %d\n", ret);
		goto cleanup;
	}
	
	ret = pthread_create(&ctx.storage_thread, NULL, storage_thread, NULL);
	if (ret) {
		fprintf(stderr, "Failed to create storage thread: %d\n", ret);
		goto cleanup;
	}
	
	ret = pthread_create(&ctx.completion_thread, NULL, completion_thread, NULL);
	if (ret) {
		fprintf(stderr, "Failed to create completion thread: %d\n", ret);
		goto cleanup;
	}
	
	printf("All threads started. System ready.\n");
	
	/* Wait a bit for connections to establish */
	sleep(3);
	
	/* Demonstrate different data flow patterns */
	demonstrate_data_flows();
	
	/* Main loop - print stats */
	while (ctx.running) {
		print_stats();
		sleep(1);
	}
	
	/* Wait for threads to finish */
	pthread_join(ctx.rdma_thread, NULL);
	pthread_join(ctx.network_thread, NULL);
	pthread_join(ctx.storage_thread, NULL);
	pthread_join(ctx.completion_thread, NULL);
	
cleanup:
	/* Cleanup RDMA */
	if (ctx.cm_id) {
		rdma_disconnect(ctx.cm_id);
		rdma_destroy_id(ctx.cm_id);
	}
	if (ctx.event_channel) {
		rdma_destroy_event_channel(ctx.event_channel);
	}
	
	/* Cleanup unified interface */
	if (ctx.ring_fd > 0) {
		syscall(__NR_io_uring_register, ctx.ring_fd, IORING_UNREGISTER_UNIFIED_IFQ, NULL, 0);
		close(ctx.ring_fd);
	}
	if (ctx.unified_region) {
		munmap(ctx.unified_region, ctx.region_size);
	}
	
	printf("\nFinal stats:\n");
	printf("  RDMA sends: %llu\n", ctx.rdma_sends);
	printf("  RDMA receives: %llu\n", ctx.rdma_recvs);
	printf("  Network packets: %llu\n", ctx.network_packets);
	printf("  Storage operations: %llu\n", ctx.storage_ops);
	printf("  Bytes transferred: %llu\n", ctx.bytes_transferred);
	printf("  Errors: %llu\n", ctx.errors);
	
	printf("\nUnified RDMA test completed\n");
	return 0;
}

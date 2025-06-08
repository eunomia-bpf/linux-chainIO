// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring unified region test
 * 
 * Demonstrates using io_uring's built-in unified I/O region
 * for zero-copy operations across network, storage, and BPF.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/nvme_ioctl.h>
#include <liburing.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define RING_SIZE	256
#define REGION_SIZE	(16 * 1024 * 1024)  /* 16MB */
#define DATA_SIZE	4096

/* Unified region control structure (mapped at offset 0) */
struct unified_control {
	struct {
		volatile uint32_t producer;
		volatile uint32_t consumer;
	} sq, cq;
	
	struct {
		volatile uint32_t producer;
		volatile uint32_t consumer;
	} net_rx, net_tx;
	
	uint64_t nvme_ops;
	uint64_t net_packets;
	uint64_t bpf_ops;
	
	uint32_t flags;
	uint32_t region_size;
	uint32_t data_offset;
	uint32_t data_size;
};

/* Test data structure */
struct test_data {
	char header[64];
	char payload[DATA_SIZE - 64];
};

/* Setup unified region using io_uring */
static int setup_unified_region(struct io_uring *ring, int nvme_fd,
				const char *net_dev)
{
	struct io_uring_unified_region_reg reg;
	struct io_uring_region_desc rd;
	int ret;
	
	memset(&rd, 0, sizeof(rd));
	rd.size = REGION_SIZE;
	rd.flags = 0;
	rd.id = 0;
	rd.mmap_offset = IORING_MAP_OFF_UNIFIED_REGION;
	
	memset(&reg, 0, sizeof(reg));
	reg.sq_entries = RING_SIZE;
	reg.cq_entries = RING_SIZE;
	reg.region_size = REGION_SIZE;
	reg.flags = 0;
	reg.nvme_fd = nvme_fd;
	reg.net_ifindex = net_dev ? if_nametoindex(net_dev) : 0;
	reg.net_rxq = 0;
	reg.region_ptr = (uint64_t)&rd;
	
	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_UNIFIED_REGION,
				&reg, 1);
	if (ret < 0) {
		fprintf(stderr, "Failed to register unified region: %s\n",
			strerror(-ret));
		return ret;
	}
	
	printf("Unified region registered:\n");
	printf("  SQ offset: %u\n", reg.offsets.sq_off);
	printf("  CQ offset: %u\n", reg.offsets.cq_off);
	printf("  Data offset: %u\n", reg.offsets.data_off);
	
	return 0;
}

/* Map unified region to userspace */
static void *map_unified_region(struct io_uring *ring, size_t size)
{
	void *ptr;
	
	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   ring->ring_fd, IORING_MAP_OFF_UNIFIED_REGION);
	if (ptr == MAP_FAILED) {
		perror("mmap unified region");
		return NULL;
	}
	
	return ptr;
}

/* Submit unified operation via io_uring */
static int submit_unified_op(struct io_uring *ring, uint16_t op_type,
			     uint64_t addr, uint32_t len)
{
	struct io_uring_sqe *sqe;
	
	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -EBUSY;
	
	sqe->opcode = IORING_OP_UNIFIED;
	sqe->flags = 0;
	sqe->fd = -1;
	sqe->off = op_type;  /* Operation type in offset field */
	sqe->addr = addr;    /* Address in unified region */
	sqe->len = len;      /* Data length */
	sqe->user_data = op_type;
	
	return 0;
}

/* Process completions */
static int process_completions(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	int ret, count = 0;
	
	while (1) {
		ret = io_uring_peek_cqe(ring, &cqe);
		if (ret < 0 || !cqe)
			break;
		
		printf("Completion: op_type=%lu, res=%d\n",
		       cqe->user_data, cqe->res);
		
		io_uring_cqe_seen(ring, cqe);
		count++;
	}
	
	return count;
}

/* Main test program */
int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct unified_control *control;
	struct test_data *data;
	char *nvme_path = "/dev/nvme0n1";
	char *net_dev = "eth0";
	void *region;
	int nvme_fd = -1;
	int ret, i;
	
	if (argc > 1)
		nvme_path = argv[1];
	if (argc > 2)
		net_dev = argv[2];
	
	/* Open NVMe device if available */
	if (access(nvme_path, R_OK | W_OK) == 0) {
		nvme_fd = open(nvme_path, O_RDWR);
		if (nvme_fd < 0) {
			fprintf(stderr, "Warning: Failed to open %s: %s\n",
				nvme_path, strerror(errno));
		}
	}
	
	/* Initialize io_uring with necessary flags */
	ret = io_uring_queue_init(256, &ring, 
				  IORING_SETUP_SQE128 | IORING_SETUP_CQE32);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init failed: %s\n",
			strerror(-ret));
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	
	/* Setup unified region */
	ret = setup_unified_region(&ring, nvme_fd, net_dev);
	if (ret < 0) {
		io_uring_queue_exit(&ring);
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	
	/* Map the region */
	region = map_unified_region(&ring, REGION_SIZE);
	if (!region) {
		io_uring_queue_exit(&ring);
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	
	/* Setup pointers */
	control = (struct unified_control *)region;
	data = (struct test_data *)((char *)region + control->data_offset);
	
	printf("\nUnified I/O Region (io_uring integrated):\n");
	printf("  Flags: 0x%x\n", control->flags);
	printf("  Region size: %u\n", control->region_size);
	printf("  Data offset: %u\n", control->data_offset);
	printf("  Data size: %u\n", control->data_size);
	
	/* Perform test operations */
	printf("\n=== Running test operations ===\n");
	
	/* Test 1: NVMe operation */
	if (nvme_fd >= 0 && (control->flags & IO_UNIFIED_F_NVME)) {
		printf("\n1. Testing NVMe operation:\n");
		strcpy(data->header, "NVMe test data");
		memset(data->payload, 0xAA, sizeof(data->payload));
		
		ret = submit_unified_op(&ring, IORING_UNIFIED_OP_NVME,
					control->data_offset, sizeof(*data));
		if (ret == 0) {
			io_uring_submit(&ring);
			printf("Submitted NVMe operation\n");
		}
	}
	
	/* Test 2: Network operation */
	if (control->flags & IO_UNIFIED_F_NETWORK) {
		printf("\n2. Testing network operation:\n");
		strcpy(data->header, "Network packet data");
		memset(data->payload, 0xBB, sizeof(data->payload));
		
		ret = submit_unified_op(&ring, IORING_UNIFIED_OP_NETWORK,
					control->data_offset, sizeof(*data));
		if (ret == 0) {
			io_uring_submit(&ring);
			printf("Submitted network operation\n");
		}
	}
	
	/* Test 3: BPF operation */
	if (control->flags & IO_UNIFIED_F_BPF) {
		printf("\n3. Testing BPF operation:\n");
		strcpy(data->header, "BPF processing data");
		memset(data->payload, 0xCC, sizeof(data->payload));
		
		ret = submit_unified_op(&ring, IORING_UNIFIED_OP_BPF,
					control->data_offset, sizeof(*data));
		if (ret == 0) {
			io_uring_submit(&ring);
			printf("Submitted BPF operation\n");
		}
	}
	
	/* Wait for completions */
	usleep(100000);
	
	/* Process completions */
	printf("\n4. Processing completions:\n");
	ret = process_completions(&ring);
	printf("Processed %d completions\n", ret);
	
	/* Print final statistics */
	printf("\nFinal statistics:\n");
	printf("  NVMe operations: %lu\n", control->nvme_ops);
	printf("  Network packets: %lu\n", control->net_packets);
	printf("  BPF operations: %lu\n", control->bpf_ops);
	
	/* Cleanup */
	munmap(region, REGION_SIZE);
	
	/* Unregister unified region */
	ret = io_uring_register(ring.ring_fd, IORING_UNREGISTER_UNIFIED_REGION,
				NULL, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to unregister unified region: %s\n",
			strerror(-ret));
	}
	
	io_uring_queue_exit(&ring);
	if (nvme_fd >= 0) close(nvme_fd);
	
	return 0;
}
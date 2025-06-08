// SPDX-License-Identifier: GPL-2.0
/*
 * Test program for unified AF_XDP style NVMe passthrough interface
 * 
 * This demonstrates how to use the unified memory region for both
 * BPF zcrx and NVMe operations in a single memory-mapped area.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* Definitions from our unified interface */
#define IORING_REGISTER_UNIFIED_IFQ	33
#define IORING_UNREGISTER_UNIFIED_IFQ	34

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

int main(int argc, char *argv[])
{
	int ring_fd, ret;
	struct io_uring_params params;
	struct io_uring_region_desc region_desc;
	struct io_unified_reg reg;
	void *ring_ptr;
	struct io_unified_ring *sq_ring, *cq_ring;
	struct io_unified_sqe *sq_entries;
	struct io_unified_cqe *cq_entries;
	void *buffers;
	const char *nvme_dev = "/dev/nvme0n1";
	
	if (argc > 1) {
		nvme_dev = argv[1];
	}
	
	printf("Testing unified AF_XDP NVMe interface with device: %s\n", nvme_dev);
	
	/* Initialize io_uring with required flags */
	memset(&params, 0, sizeof(params));
	params.flags = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32 | 
		       IORING_SETUP_SQE128;
	
	ring_fd = syscall(__NR_io_uring_setup, 256, &params);
	if (ring_fd < 0) {
		perror("io_uring_setup");
		return 1;
	}
	
	printf("Created io_uring with fd %d\n", ring_fd);
	
	/* Allocate unified memory region */
	size_t total_size = 
		2 * sizeof(struct io_unified_ring) +      /* SQ and CQ rings */
		256 * sizeof(struct io_unified_sqe) +     /* SQ entries */
		256 * sizeof(struct io_unified_cqe) +     /* CQ entries */
		1024 * 4096;                              /* 1024 4KB buffers */
	
	ring_ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (ring_ptr == MAP_FAILED) {
		perror("mmap");
		close(ring_fd);
		return 1;
	}
	
	printf("Allocated %zu bytes for unified region at %p\n", total_size, ring_ptr);
	
	/* Set up region descriptor */
	memset(&region_desc, 0, sizeof(region_desc));
	region_desc.user_addr = (__u64)(uintptr_t)ring_ptr;
	region_desc.size = total_size;
	
	/* Set up registration structure */
	memset(&reg, 0, sizeof(reg));
	reg.region_ptr = (__u64)(uintptr_t)&region_desc;
	reg.nvme_dev_path = (__u64)(uintptr_t)nvme_dev;
	reg.sq_entries = 256;
	reg.cq_entries = 256;
	reg.buffer_entries = 1024;
	reg.buffer_entry_size = 4096;
	
	/* Register unified interface */
	ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_UNIFIED_IFQ,
		      &reg, 1);
	if (ret < 0) {
		perror("io_uring_register unified ifq");
		munmap(ring_ptr, total_size);
		close(ring_fd);
		return 1;
	}
	
	printf("Successfully registered unified interface\n");
	
	/* Map ring structures */
	sq_ring = (struct io_unified_ring *)((char *)ring_ptr + reg.offsets.sq_ring);
	cq_ring = (struct io_unified_ring *)((char *)ring_ptr + reg.offsets.cq_ring);
	sq_entries = (struct io_unified_sqe *)((char *)ring_ptr + reg.offsets.sq_entries);
	cq_entries = (struct io_unified_cqe *)((char *)ring_ptr + reg.offsets.cq_entries);
	buffers = (char *)ring_ptr + reg.offsets.buffers;
	
	printf("Ring structures mapped:\n");
	printf("  SQ ring: %p (entries: %u)\n", sq_ring, sq_ring->ring_entries);
	printf("  CQ ring: %p (entries: %u)\n", cq_ring, cq_ring->ring_entries);
	printf("  SQ entries: %p\n", sq_entries);
	printf("  CQ entries: %p\n", cq_entries);
	printf("  Buffers: %p\n", buffers);
	
	/* Example: Submit a simple NVMe identify command */
	struct io_unified_sqe *sqe = &sq_entries[0];
	memset(sqe, 0, sizeof(*sqe));
	
	/* Fill NVMe command for identify controller */
	sqe->nvme_cmd.opcode = 0x06;  /* Identify */
	sqe->nvme_cmd.nsid = 0;       /* Controller identify */
	sqe->nvme_cmd.cdw10 = 1;      /* CNS = 1 (Controller) */
	sqe->nvme_cmd.data_len = 4096;
	sqe->nvme_cmd.addr = (__u64)(uintptr_t)buffers;  /* First buffer */
	
	sqe->buf_offset = 0;          /* Use first buffer */
	sqe->user_data = 0x12345678;  /* Correlation ID */
	
	/* Submit the command */
	sq_ring->producer = 1;
	__sync_synchronize();  /* Memory barrier */
	
	printf("Submitted NVMe identify command\n");
	
	/* Poll for completion */
	int completed = 0;
	for (int i = 0; i < 1000 && !completed; i++) {
		__sync_synchronize();
		if (cq_ring->producer != cq_ring->consumer) {
			struct io_unified_cqe *cqe = &cq_entries[cq_ring->consumer & cq_ring->ring_mask];
			
			printf("Completion received:\n");
			printf("  user_data: 0x%llx\n", cqe->user_data);
			printf("  result: %d\n", cqe->result);
			printf("  status: %u\n", cqe->status);
			printf("  length: %u\n", cqe->len);
			
			/* Print first few bytes of identify data */
			if (cqe->len >= 16) {
				unsigned char *data = (unsigned char *)buffers;
				printf("  Identify data: ");
				for (int j = 0; j < 16; j++) {
					printf("%02x ", data[j]);
				}
				printf("\n");
			}
			
			cq_ring->consumer++;
			completed = 1;
		}
		usleep(1000);  /* Wait 1ms */
	}
	
	if (!completed) {
		printf("No completion received within timeout\n");
	}
	
	/* Cleanup */
	ret = syscall(__NR_io_uring_register, ring_fd, IORING_UNREGISTER_UNIFIED_IFQ,
		      NULL, 0);
	if (ret < 0) {
		perror("io_uring_register unregister unified ifq");
	} else {
		printf("Successfully unregistered unified interface\n");
	}
	
	munmap(ring_ptr, total_size);
	close(ring_fd);
	
	printf("Test completed\n");
	return 0;
}
// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe Ring I/O test program
 * 
 * This program demonstrates how to use the nvme_ring_io kernel module
 * to perform NVMe passthrough operations using AF_XDP style ring buffers
 * integrated with io_uring fixed buffers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <liburing.h>
#include "../../include/uapi/linux/nvme_ring_io.h"

#define RING_SIZE	256
#define DATA_SIZE	(4 * 1024 * 1024)  /* 4MB data area */
#define BLOCK_SIZE	4096

/* Ring buffer mapping structure */
struct ring_buffer {
	/* Indices - first page */
	struct {
		volatile uint32_t producer;
		volatile uint32_t consumer;
	} *sq, *cq;
	
	/* Descriptors */
	uint64_t *sq_descs;
	uint64_t *cq_descs;
	
	/* Data area */
	void *data_area;
	size_t data_size;
	
	/* Memory mapping */
	void *mmap_addr;
	size_t mmap_size;
};

/* Initialize ring buffer */
static int init_ring_buffer(struct ring_buffer *ring, int fd, 
			    uint32_t sq_entries, uint32_t cq_entries,
			    size_t data_size)
{
	size_t total_size;
	void *addr;
	
	/* Calculate total size needed */
	total_size = 4096 +  /* Indices page */
		     sq_entries * sizeof(uint64_t) +  /* SQ descriptors */
		     cq_entries * sizeof(uint64_t) +  /* CQ descriptors */
		     data_size;  /* Data area */
	
	/* Map the ring buffer */
	addr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	ring->mmap_addr = addr;
	ring->mmap_size = total_size;
	
	/* Setup pointers */
	ring->sq = (void *)addr;
	ring->cq = (void *)((char *)addr + 64);  /* Offset for CQ indices */
	
	/* Descriptors start after the indices page */
	ring->sq_descs = (uint64_t *)((char *)addr + 4096);
	ring->cq_descs = (uint64_t *)((char *)ring->sq_descs + sq_entries * sizeof(uint64_t));
	
	/* Data area */
	ring->data_area = (char *)ring->cq_descs + cq_entries * sizeof(uint64_t);
	ring->data_size = data_size;
	
	return 0;
}

/* Submit an NVMe read command */
static int submit_nvme_read(struct ring_buffer *ring, int ring_fd,
			    uint64_t lba, uint32_t block_count, void *buffer)
{
	struct nvme_command *cmd;
	struct nvme_ring_submit submit;
	uint32_t sq_tail;
	uint64_t desc_addr;
	
	/* Get next SQ entry */
	sq_tail = ring->sq->producer;
	if (((sq_tail + 1) & (RING_SIZE - 1)) == ring->sq->consumer) {
		fprintf(stderr, "SQ full\n");
		return -EBUSY;
	}
	
	/* Prepare NVMe command in data area */
	cmd = (struct nvme_command *)((char *)ring->data_area + sq_tail * BLOCK_SIZE);
	memset(cmd, 0, sizeof(*cmd));
	
	cmd->rw.opcode = 0x02;  /* NVMe Read */
	cmd->rw.nsid = 1;
	cmd->rw.slba = lba;
	cmd->rw.length = block_count - 1;
	
	/* Calculate descriptor address */
	desc_addr = (uint64_t)cmd;
	
	/* Update SQ descriptor */
	ring->sq_descs[sq_tail] = desc_addr;
	
	/* Submit via ioctl */
	submit.desc_addr = desc_addr;
	submit.count = 1;
	submit.flags = 0;
	
	if (ioctl(ring_fd, NVME_RING_IO_SUBMIT, &submit) < 0) {
		perror("ioctl(NVME_RING_IO_SUBMIT)");
		return -1;
	}
	
	/* Update producer */
	__sync_synchronize();
	ring->sq->producer = (sq_tail + 1) & (RING_SIZE - 1);
	
	return 0;
}

/* Process completions */
static int process_completions(struct ring_buffer *ring, int ring_fd)
{
	struct nvme_ring_complete complete;
	int ret;
	
	/* Request completions via ioctl */
	ret = ioctl(ring_fd, NVME_RING_IO_COMPLETE, &complete);
	if (ret < 0) {
		perror("ioctl(NVME_RING_IO_COMPLETE)");
		return -1;
	}
	
	printf("Processed %u completions\n", complete.count);
	
	/* Update consumer index */
	if (complete.count > 0) {
		uint32_t cq_head = ring->cq->consumer;
		ring->cq->consumer = (cq_head + complete.count) & (RING_SIZE - 1);
	}
	
	return complete.count;
}

/* Print ring statistics */
static void print_ring_info(int ring_fd)
{
	struct nvme_ring_info info;
	
	if (ioctl(ring_fd, NVME_RING_IO_GET_INFO, &info) < 0) {
		perror("ioctl(NVME_RING_IO_GET_INFO)");
		return;
	}
	
	printf("\nRing Statistics:\n");
	printf("  SQ: entries=%u, head=%lu, tail=%lu\n", 
	       info.sq_entries, info.sq_head, info.sq_tail);
	printf("  CQ: entries=%u, head=%lu, tail=%lu\n",
	       info.cq_entries, info.cq_head, info.cq_tail);
	printf("  Submitted: %lu, Completed: %lu\n",
	       info.submitted, info.completed);
}

int main(int argc, char *argv[])
{
	struct io_uring uring;
	struct nvme_ring_setup setup;
	struct ring_buffer ring;
	char *nvme_path = "/dev/nvme0n1";
	int nvme_fd, ring_fd, uring_fd;
	int ret;
	
	if (argc > 1)
		nvme_path = argv[1];
	
	/* Open NVMe device */
	nvme_fd = open(nvme_path, O_RDWR);
	if (nvme_fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", nvme_path, strerror(errno));
		return 1;
	}
	
	/* Setup io_uring */
	ret = io_uring_queue_init(256, &uring, IORING_SETUP_SQE128 | IORING_SETUP_CQE32);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init failed: %s\n", strerror(-ret));
		close(nvme_fd);
		return 1;
	}
	uring_fd = uring.ring_fd;
	
	/* Open ring device */
	ring_fd = open("/dev/nvme_ring_io", O_RDWR);
	if (ring_fd < 0) {
		fprintf(stderr, "Failed to open /dev/nvme_ring_io: %s\n", strerror(errno));
		io_uring_queue_exit(&uring);
		close(nvme_fd);
		return 1;
	}
	
	/* Setup ring buffer */
	memset(&setup, 0, sizeof(setup));
	setup.sq_entries = RING_SIZE;
	setup.cq_entries = RING_SIZE;
	setup.data_size = DATA_SIZE;
	setup.nvme_fd = nvme_fd;
	setup.uring_fd = uring_fd;
	setup.flags = 0;
	
	ret = ioctl(ring_fd, NVME_RING_IO_SETUP, &setup);
	if (ret < 0) {
		fprintf(stderr, "ioctl(NVME_RING_IO_SETUP) failed: %s\n", strerror(errno));
		close(ring_fd);
		io_uring_queue_exit(&uring);
		close(nvme_fd);
		return 1;
	}
	
	/* Initialize ring buffer mapping */
	ret = init_ring_buffer(&ring, ring_fd, RING_SIZE, RING_SIZE, DATA_SIZE);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize ring buffer\n");
		close(ring_fd);
		io_uring_queue_exit(&uring);
		close(nvme_fd);
		return 1;
	}
	
	printf("NVMe Ring I/O initialized successfully\n");
	printf("  NVMe device: %s\n", nvme_path);
	printf("  Ring size: SQ=%d, CQ=%d\n", RING_SIZE, RING_SIZE);
	printf("  Data area: %zu bytes\n", DATA_SIZE);
	
	/* Perform some test operations */
	printf("\nSubmitting test reads...\n");
	
	/* Submit a few read commands */
	for (int i = 0; i < 5; i++) {
		ret = submit_nvme_read(&ring, ring_fd, i * 8, 8, NULL);
		if (ret < 0) {
			fprintf(stderr, "Failed to submit read %d\n", i);
			break;
		}
		printf("Submitted read %d: LBA=%d, blocks=8\n", i, i * 8);
	}
	
	/* Wait a bit for completions */
	usleep(10000);
	
	/* Process completions */
	printf("\nProcessing completions...\n");
	ret = process_completions(&ring, ring_fd);
	
	/* Print statistics */
	print_ring_info(ring_fd);
	
	/* Cleanup */
	munmap(ring.mmap_addr, ring.mmap_size);
	close(ring_fd);
	io_uring_queue_exit(&uring);
	close(nvme_fd);
	
	return 0;
}
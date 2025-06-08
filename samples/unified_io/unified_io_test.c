// SPDX-License-Identifier: GPL-2.0
/*
 * Unified I/O Region test program
 * 
 * Demonstrates using a single memory region for:
 * - NVMe storage operations
 * - Network packet processing
 * - BPF program execution
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
#include <linux/if_packet.h>
#include <linux/nvme_ioctl.h>
#include <liburing.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/uapi/linux/unified_io_region.h"

#define REGION_SIZE	(16 * 1024 * 1024)  /* 16MB unified region */
#define RING_SIZE	256
#define DATA_BLOCK_SIZE	4096

/* Unified region mapping */
struct unified_region_map {
	struct unified_control *control;
	struct unified_descriptor *sq_descs;
	struct unified_descriptor *cq_descs;
	void *data_area;
	size_t data_size;
	void *mmap_addr;
	size_t mmap_size;
};

/* Simple BPF program that processes data in the unified region */
const char *bpf_program_text = "\
#include <linux/bpf.h>\n\
#include <bpf/bpf_helpers.h>\n\
\n\
struct unified_bpf_ctx {\n\
	void *region;\n\
	void *desc;\n\
	void *data;\n\
	__u32 data_len;\n\
};\n\
\n\
SEC(\"unified_io\")\n\
int process_unified_data(struct unified_bpf_ctx *ctx)\n\
{\n\
	char *data = ctx->data;\n\
	int i;\n\
	\n\
	/* Simple XOR operation on data */\n\
	for (i = 0; i < ctx->data_len && i < 64; i++) {\n\
		data[i] ^= 0x42;\n\
	}\n\
	\n\
	return 0;\n\
}\n\
\n\
char _license[] SEC(\"license\") = \"GPL\";\n\
";

/* Initialize unified region mapping */
static int init_unified_region(struct unified_region_map *map, int fd, size_t size)
{
	void *addr;
	
	/* Map the unified region */
	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	map->mmap_addr = addr;
	map->mmap_size = size;
	
	/* Setup pointers based on layout */
	map->control = (struct unified_control *)addr;
	
	/* Descriptors start after control page */
	map->sq_descs = (struct unified_descriptor *)((char *)addr + 4096);
	map->cq_descs = map->sq_descs + RING_SIZE;
	
	/* Data area location from control structure */
	map->data_area = (char *)addr + map->control->data_offset;
	map->data_size = map->control->data_size;
	
	printf("Unified region mapped:\n");
	printf("  Control: %p\n", map->control);
	printf("  SQ descriptors: %p\n", map->sq_descs);
	printf("  CQ descriptors: %p\n", map->cq_descs);
	printf("  Data area: %p (size: %zu)\n", map->data_area, map->data_size);
	printf("  Flags: 0x%x\n", map->control->flags);
	
	return 0;
}

/* Submit an NVMe operation */
static int submit_nvme_op(struct unified_region_map *map, int fd,
			  uint64_t lba, uint32_t blocks, bool is_write)
{
	struct unified_io_submit submit;
	struct nvme_command *cmd;
	uint32_t sq_tail;
	
	/* Get next SQ slot */
	sq_tail = map->control->sq.producer;
	if (((sq_tail + 1) & (RING_SIZE - 1)) == map->control->sq.consumer) {
		fprintf(stderr, "SQ full\n");
		return -EBUSY;
	}
	
	/* Prepare NVMe command in data area */
	cmd = (struct nvme_command *)((char *)map->data_area + sq_tail * DATA_BLOCK_SIZE);
	memset(cmd, 0, sizeof(*cmd));
	
	cmd->rw.opcode = is_write ? UNIFIED_NVME_OPC_WRITE : UNIFIED_NVME_OPC_READ;
	cmd->rw.nsid = 1;
	cmd->rw.slba = lba;
	cmd->rw.length = blocks - 1;
	
	/* Setup descriptor */
	submit.desc.addr = sq_tail * DATA_BLOCK_SIZE;
	submit.desc.len = blocks * 512;  /* 512 bytes per block */
	submit.desc.flags = is_write ? UNIFIED_DESC_F_WRITE : UNIFIED_DESC_F_READ;
	submit.desc.type = UNIFIED_REGION_F_NVME;
	submit.desc.nvme.opcode = cmd->rw.opcode;
	submit.desc.nvme.nsid = 1;
	
	/* Submit via ioctl */
	if (ioctl(fd, UNIFIED_IO_SUBMIT, &submit) < 0) {
		perror("ioctl(UNIFIED_IO_SUBMIT)");
		return -1;
	}
	
	/* Update producer */
	__sync_synchronize();
	map->control->sq.producer = (sq_tail + 1) & (RING_SIZE - 1);
	
	printf("Submitted NVMe %s: LBA=%lu, blocks=%u\n",
	       is_write ? "write" : "read", lba, blocks);
	
	return 0;
}

/* Submit a network operation */
static int submit_network_op(struct unified_region_map *map, int fd,
			     void *packet_data, size_t packet_len)
{
	struct unified_io_submit submit;
	uint32_t sq_tail;
	void *data_ptr;
	
	/* Get next SQ slot */
	sq_tail = map->control->sq.producer;
	if (((sq_tail + 1) & (RING_SIZE - 1)) == map->control->sq.consumer) {
		fprintf(stderr, "SQ full\n");
		return -EBUSY;
	}
	
	/* Copy packet data to data area */
	data_ptr = (char *)map->data_area + sq_tail * DATA_BLOCK_SIZE;
	memcpy(data_ptr, packet_data, packet_len);
	
	/* Setup descriptor */
	submit.desc.addr = sq_tail * DATA_BLOCK_SIZE;
	submit.desc.len = packet_len;
	submit.desc.flags = 0;
	submit.desc.type = UNIFIED_REGION_F_NETWORK;
	submit.desc.net.proto = UNIFIED_NET_PROTO_RAW;
	submit.desc.net.port = 0;
	
	/* Submit via ioctl */
	if (ioctl(fd, UNIFIED_IO_SUBMIT, &submit) < 0) {
		perror("ioctl(UNIFIED_IO_SUBMIT)");
		return -1;
	}
	
	/* Update producer */
	__sync_synchronize();
	map->control->sq.producer = (sq_tail + 1) & (RING_SIZE - 1);
	
	printf("Submitted network packet: len=%zu\n", packet_len);
	
	return 0;
}

/* Submit a BPF operation */
static int submit_bpf_op(struct unified_region_map *map, int fd,
			 void *data, size_t data_len)
{
	struct unified_io_submit submit;
	uint32_t sq_tail;
	void *data_ptr;
	
	/* Get next SQ slot */
	sq_tail = map->control->sq.producer;
	if (((sq_tail + 1) & (RING_SIZE - 1)) == map->control->sq.consumer) {
		fprintf(stderr, "SQ full\n");
		return -EBUSY;
	}
	
	/* Copy data to data area */
	data_ptr = (char *)map->data_area + sq_tail * DATA_BLOCK_SIZE;
	memcpy(data_ptr, data, data_len);
	
	/* Setup descriptor */
	submit.desc.addr = sq_tail * DATA_BLOCK_SIZE;
	submit.desc.len = data_len;
	submit.desc.flags = 0;
	submit.desc.type = UNIFIED_REGION_F_BPF;
	submit.desc.bpf.prog_id = 0;  /* Will use attached program */
	
	/* Submit via ioctl */
	if (ioctl(fd, UNIFIED_IO_SUBMIT, &submit) < 0) {
		perror("ioctl(UNIFIED_IO_SUBMIT)");
		return -1;
	}
	
	/* Update producer */
	__sync_synchronize();
	map->control->sq.producer = (sq_tail + 1) & (RING_SIZE - 1);
	
	printf("Submitted BPF operation: len=%zu\n", data_len);
	
	return 0;
}

/* Process completions */
static int process_completions(struct unified_region_map *map, int fd)
{
	struct unified_io_complete complete;
	int ret;
	
	ret = ioctl(fd, UNIFIED_IO_COMPLETE, &complete);
	if (ret < 0) {
		perror("ioctl(UNIFIED_IO_COMPLETE)");
		return -1;
	}
	
	if (complete.count > 0) {
		uint32_t cq_head = map->control->cq.consumer;
		map->control->cq.consumer = (cq_head + complete.count) & (RING_SIZE - 1);
		printf("Processed %u completions\n", complete.count);
	}
	
	return complete.count;
}

/* Print region statistics */
static void print_stats(int fd)
{
	struct unified_io_info info;
	
	if (ioctl(fd, UNIFIED_IO_GET_INFO, &info) < 0) {
		perror("ioctl(UNIFIED_IO_GET_INFO)");
		return;
	}
	
	printf("\nUnified Region Statistics:\n");
	printf("  NVMe operations: %lu\n", info.nvme_ops);
	printf("  Network packets: %lu\n", info.net_packets);
	printf("  BPF operations: %lu\n", info.bpf_ops);
	printf("  Total submitted: %lu\n", info.submitted);
	printf("  Total completed: %lu\n", info.completed);
	printf("  SQ: head=%u, tail=%u\n", info.sq_head, info.sq_tail);
	printf("  CQ: head=%u, tail=%u\n", info.cq_head, info.cq_tail);
}

/* Load and attach a simple BPF program */
static int attach_bpf_program(int fd)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct unified_io_bpf bpf_cfg;
	char obj_file[] = "/tmp/unified_bpf.o";
	FILE *f;
	int prog_fd;
	
	/* Write BPF program to temporary file */
	f = fopen("/tmp/unified_bpf.c", "w");
	if (!f) {
		perror("fopen");
		return -1;
	}
	fprintf(f, "%s", bpf_program_text);
	fclose(f);
	
	/* Compile BPF program */
	if (system("clang -O2 -target bpf -c /tmp/unified_bpf.c -o /tmp/unified_bpf.o") != 0) {
		fprintf(stderr, "Failed to compile BPF program\n");
		return -1;
	}
	
	/* Load BPF object */
	obj = bpf_object__open_file(obj_file, NULL);
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object\n");
		return -1;
	}
	
	if (bpf_object__load(obj)) {
		fprintf(stderr, "Failed to load BPF object\n");
		bpf_object__close(obj);
		return -1;
	}
	
	/* Get program */
	prog = bpf_object__find_program_by_name(obj, "process_unified_data");
	if (!prog) {
		fprintf(stderr, "Failed to find BPF program\n");
		bpf_object__close(obj);
		return -1;
	}
	
	prog_fd = bpf_program__fd(prog);
	
	/* Attach to unified region */
	bpf_cfg.prog_fd = prog_fd;
	bpf_cfg.flags = 0;
	
	if (ioctl(fd, UNIFIED_IO_ATTACH_BPF, &bpf_cfg) < 0) {
		perror("ioctl(UNIFIED_IO_ATTACH_BPF)");
		bpf_object__close(obj);
		return -1;
	}
	
	printf("BPF program attached successfully\n");
	
	/* Note: In real usage, we would keep the object open */
	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring uring;
	struct unified_io_setup setup;
	struct unified_region_map map;
	char *nvme_path = "/dev/nvme0n1";
	char *net_dev = "eth0";
	int nvme_fd, uring_fd, unified_fd;
	int ret;
	
	/* Parse arguments */
	if (argc > 1)
		nvme_path = argv[1];
	if (argc > 2)
		net_dev = argv[2];
	
	/* Open NVMe device */
	nvme_fd = open(nvme_path, O_RDWR);
	if (nvme_fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", nvme_path, strerror(errno));
		fprintf(stderr, "Continuing without NVMe support\n");
		nvme_fd = -1;
	}
	
	/* Setup io_uring */
	ret = io_uring_queue_init(256, &uring, IORING_SETUP_SQE128 | IORING_SETUP_CQE32);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init failed: %s\n", strerror(-ret));
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	uring_fd = uring.ring_fd;
	
	/* Open unified I/O device */
	unified_fd = open("/dev/unified_io_region", O_RDWR);
	if (unified_fd < 0) {
		fprintf(stderr, "Failed to open /dev/unified_io_region: %s\n", strerror(errno));
		io_uring_queue_exit(&uring);
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	
	/* Setup unified region */
	memset(&setup, 0, sizeof(setup));
	setup.sq_entries = RING_SIZE;
	setup.cq_entries = RING_SIZE;
	setup.region_size = REGION_SIZE;
	setup.nvme_fd = nvme_fd;
	setup.uring_fd = uring_fd;
	setup.net_ifindex = if_nametoindex(net_dev);
	setup.net_rxq = 0;
	setup.flags = 0;
	
	ret = ioctl(unified_fd, UNIFIED_IO_SETUP, &setup);
	if (ret < 0) {
		fprintf(stderr, "ioctl(UNIFIED_IO_SETUP) failed: %s\n", strerror(errno));
		close(unified_fd);
		io_uring_queue_exit(&uring);
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	
	/* Initialize region mapping */
	ret = init_unified_region(&map, unified_fd, REGION_SIZE);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize unified region\n");
		close(unified_fd);
		io_uring_queue_exit(&uring);
		if (nvme_fd >= 0) close(nvme_fd);
		return 1;
	}
	
	/* Attach BPF program */
	if (attach_bpf_program(unified_fd) < 0) {
		fprintf(stderr, "Failed to attach BPF program\n");
		/* Continue without BPF */
	}
	
	printf("\nUnified I/O Region initialized successfully\n");
	printf("  NVMe device: %s\n", nvme_path);
	printf("  Network device: %s (index: %d)\n", net_dev, setup.net_ifindex);
	printf("  Region size: %u bytes\n", setup.region_size);
	
	/* Perform test operations */
	printf("\n=== Running test operations ===\n");
	
	/* Test 1: NVMe operations */
	if (nvme_fd >= 0 && (map.control->flags & UNIFIED_REGION_F_NVME)) {
		printf("\n1. Testing NVMe operations:\n");
		for (int i = 0; i < 3; i++) {
			ret = submit_nvme_op(&map, unified_fd, i * 8, 8, false);
			if (ret < 0)
				break;
		}
	}
	
	/* Test 2: Network operations */
	if (map.control->flags & UNIFIED_REGION_F_NETWORK) {
		printf("\n2. Testing network operations:\n");
		char packet_data[] = "Hello, unified I/O region!";
		for (int i = 0; i < 3; i++) {
			ret = submit_network_op(&map, unified_fd, packet_data, sizeof(packet_data));
			if (ret < 0)
				break;
		}
	}
	
	/* Test 3: BPF operations */
	if (map.control->flags & UNIFIED_REGION_F_BPF) {
		printf("\n3. Testing BPF operations:\n");
		char bpf_data[] = "Process this data with BPF";
		for (int i = 0; i < 3; i++) {
			ret = submit_bpf_op(&map, unified_fd, bpf_data, sizeof(bpf_data));
			if (ret < 0)
				break;
		}
	}
	
	/* Wait a bit for operations to complete */
	usleep(100000);
	
	/* Process completions */
	printf("\n4. Processing completions:\n");
	ret = process_completions(&map, unified_fd);
	
	/* Print final statistics */
	print_stats(unified_fd);
	
	/* Cleanup */
	munmap(map.mmap_addr, map.mmap_size);
	close(unified_fd);
	io_uring_queue_exit(&uring);
	if (nvme_fd >= 0) close(nvme_fd);
	
	return 0;
}
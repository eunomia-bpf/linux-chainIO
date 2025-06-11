#include <stdio.h>
#include <stdint.h>
#include "include/uapi/linux/io_uring.h"

// Simple approximations of the structs from unified.h
struct io_unified_ring {
    uint32_t producer;
    uint32_t consumer;
    uint32_t cached_producer;
    uint32_t cached_consumer;
    uint32_t flags;
    uint32_t ring_entries;
    uint64_t ring_mask;
    uint64_t ring_size;
};

struct nvme_uring_cmd {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t rsvd1;
    uint32_t nsid;
    uint32_t cdw2;
    uint32_t cdw3;
    uint64_t metadata;
    uint64_t addr;
    uint32_t metadata_len;
    uint32_t data_len;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
    uint32_t timeout_ms;
    uint32_t rsvd2;
};

struct io_unified_sqe {
    struct nvme_uring_cmd nvme_cmd;
    uint64_t buf_offset;
    uint64_t user_data;
    uint32_t flags;
    uint32_t __pad;
};

struct io_unified_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t status;
    uint64_t dma_addr;
    uint32_t len;
    uint32_t flags;
};

int main() {
    printf("Structure sizes:\n");
    printf("  io_unified_ring: %zu bytes\n", sizeof(struct io_unified_ring));
    printf("  io_unified_sqe: %zu bytes\n", sizeof(struct io_unified_sqe));
    printf("  io_unified_cqe: %zu bytes\n", sizeof(struct io_unified_cqe));
    printf("  nvme_uring_cmd: %zu bytes\n", sizeof(struct nvme_uring_cmd));
    
    uint32_t sq_entries = 256;
    uint32_t cq_entries = 256;
    uint32_t buffer_entries = 1024;
    uint32_t buffer_entry_size = 4096;
    
    size_t ring_size = 2 * sizeof(struct io_unified_ring);
    size_t entries_size = (sq_entries * sizeof(struct io_unified_sqe)) +
                          (cq_entries * sizeof(struct io_unified_cqe));
    size_t buffer_size = buffer_entries * buffer_entry_size;
    size_t total_size = ring_size + entries_size + buffer_size;
    
    printf("\nCalculated sizes for 256/256/1024 entries:\n");
    printf("  ring_size: %zu bytes\n", ring_size);
    printf("  entries_size: %zu bytes\n", entries_size);
    printf("  buffer_size: %zu bytes\n", buffer_size);
    printf("  total_size: %zu bytes\n", total_size);
    
    size_t test_alloc = 1024 * 1024; // What our test allocates
    printf("\nTest program allocation: %zu bytes\n", test_alloc);
    printf("Required vs allocated: %s\n", total_size <= test_alloc ? "OK" : "TOO SMALL");
    
    return 0;
}
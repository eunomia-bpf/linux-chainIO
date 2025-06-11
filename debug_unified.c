#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <linux/types.h>

#define IORING_REGISTER_UNIFIED_IFQ 33

#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#define IORING_SETUP_CQE32 (1U << 11)
#define IORING_SETUP_SQE128 (1U << 10)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)

struct io_uring_params {
    __u32 sq_entries;
    __u32 cq_entries;
    __u32 flags;
    __u32 sq_thread_cpu;
    __u32 sq_thread_idle;
    __u32 features;
    __u32 wq_fd;
    __u32 resv[3];
    __u32 sq_off_unused[3];
    __u32 cq_off_unused[4];
};

struct io_uring_region_desc {
    __u64 user_addr;
    __u64 size;
    __u32 flags;
    __u32 __resv[3];
};

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

int main() {
    struct io_uring_params params = {0};
    params.flags = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32 | 
                   IORING_SETUP_SQE128 | IORING_SETUP_SINGLE_ISSUER;
    int ring_fd, ret;
    size_t region_size = 8 * 1024 * 1024; // 8MB to be safe
    void *region;
    struct io_uring_region_desc rd = {0};
    struct io_unified_reg reg = {0};
    const char *nvme_path = "/dev/nvme0n1";
    
    printf("Creating io_uring...\n");
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }
    printf("io_uring_setup succeeded, fd: %d\n", ring_fd);
    
    printf("Allocating region (%zu bytes)...\n", region_size);
    region = mmap(NULL, region_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        close(ring_fd);
        return 1;
    }
    printf("Region allocated at %p\n", region);
    
    rd.user_addr = (__u64)(uintptr_t)region;
    rd.size = region_size;
    
    reg.region_ptr = (__u64)(uintptr_t)&rd;
    reg.nvme_dev_path = (__u64)(uintptr_t)nvme_path;
    reg.sq_entries = 32;
    reg.cq_entries = 32;
    reg.buffer_entries = 64;
    reg.buffer_entry_size = 1024;
    
    printf("Attempting unified interface registration...\n");
    printf("  region_ptr: %p\n", (void*)reg.region_ptr);
    printf("  nvme_dev_path: %s\n", nvme_path);
    printf("  sq_entries: %u\n", reg.sq_entries);
    printf("  cq_entries: %u\n", reg.cq_entries);
    printf("  buffer_entries: %u\n", reg.buffer_entries);
    printf("  buffer_entry_size: %u\n", reg.buffer_entry_size);
    
    ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_UNIFIED_IFQ, &reg, 1);
    if (ret < 0) {
        printf("io_uring_register failed: %s (errno: %d)\n", strerror(errno), errno);
        printf("Return value: %d\n", ret);
    } else {
        printf("Unified interface registered successfully!\n");
    }
    
    munmap(region, region_size);
    close(ring_fd);
    return 0;
}
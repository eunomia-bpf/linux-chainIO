#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include "../../../../include/uapi/linux/io_uring.h"

#define IORING_REGISTER_UNIFIED_RDMA_IFQ 50

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
    __u16 pkey_index;
    __u8 timeout;
    __u8 retry_cnt;
    __u8 rnr_retry;
    __u8 min_rnr_timer;
    __u16 __resv[2];
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

struct io_unified_rdma_reg {
    struct io_unified_reg base;
    
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

int main()
{
    struct io_uring_params params;
    struct io_uring_region_desc region_desc;
    struct io_unified_rdma_reg rdma_reg;
    int ring_fd, ret;
    void *region;
    size_t region_size = 16 * 1024 * 1024; // 16MB
    size_t page_size = getpagesize();
    
    printf("Testing minimal RDMA registration...\n");
    
    // Round up to page boundary
    region_size = (region_size + page_size - 1) & ~(page_size - 1);
    
    // Create io_uring
    memset(&params, 0, sizeof(params));
    params.flags = 0;
    
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }
    printf("io_uring_setup succeeded, fd: %d\n", ring_fd);
    
    // Allocate memory region
    region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        close(ring_fd);
        return 1;
    }
    printf("Allocated memory region: %p, size: %zu\n", region, region_size);
    
    // Set up region descriptor
    memset(&region_desc, 0, sizeof(region_desc));
    region_desc.user_addr = (__u64)(uintptr_t)region;
    region_desc.size = region_size;
    region_desc.flags = IORING_MEM_REGION_TYPE_USER;
    region_desc.id = 0;
    region_desc.mmap_offset = 0;
    
    // Set up minimal RDMA registration
    memset(&rdma_reg, 0, sizeof(rdma_reg));
    rdma_reg.base.region_ptr = (__u64)(uintptr_t)&region_desc;
    rdma_reg.base.nvme_dev_path = (__u64)(uintptr_t)"/dev/nvme0n1";
    rdma_reg.base.sq_entries = 256;
    rdma_reg.base.cq_entries = 256;
    rdma_reg.base.buffer_entries = 1024;
    rdma_reg.base.buffer_entry_size = 4096;
    
    rdma_reg.rdma_dev_name = (__u64)(uintptr_t)"roceo12409";
    rdma_reg.rdma_port = 1;
    rdma_reg.transport_type = 2; // IBV_QPT_RC
    
    rdma_reg.qp_config.transport_type = 2;
    rdma_reg.qp_config.max_send_wr = 256;
    rdma_reg.qp_config.max_recv_wr = 256;
    rdma_reg.qp_config.max_send_sge = 16;
    rdma_reg.qp_config.max_recv_sge = 16;
    rdma_reg.qp_config.max_inline_data = 256;
    
    rdma_reg.num_mrs = 64;
    
    printf("Calling io_uring_register(IORING_REGISTER_UNIFIED_RDMA_IFQ)...\n");
    ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_UNIFIED_RDMA_IFQ,
                  &rdma_reg, 1);
    
    if (ret < 0) {
        printf("io_uring_register failed: %s (errno: %d)\n", strerror(errno), errno);
        
        if (errno == EOPNOTSUPP) {
            printf("  -> RDMA interface not supported\n");
        } else if (errno == EINVAL) {
            printf("  -> Invalid parameters\n");
        } else if (errno == EPERM) {
            printf("  -> Permission denied\n");
        }
    } else {
        printf("io_uring_register succeeded!\n");
    }
    
    munmap(region, region_size);
    close(ring_fd);
    return ret < 0 ? 1 : 0;
}
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#define __NR_io_uring_setup 425
#define __NR_io_uring_register 427

#define IORING_REGISTER_PROBE 8
#define IORING_REGISTER_ZCRX_IFQ 32
#define IORING_REGISTER_UNIFIED_IFQ 33

struct io_uring_params {
    unsigned int sq_entries;
    unsigned int cq_entries;
    unsigned int flags;
    unsigned int sq_thread_cpu;
    unsigned int sq_thread_idle;
    unsigned int features;
    unsigned int wq_fd;
    unsigned int resv[3];
    unsigned long long sq_off[11];
    unsigned long long cq_off[9];
};

int main() {
    int ring_fd;
    struct io_uring_params params = {0};
    
    printf("Testing io_uring operation availability...\n");
    
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }
    
    printf("io_uring setup successful, fd: %d\n", ring_fd);
    
    // Test ZCRX interface (should exist according to config)
    int ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_ZCRX_IFQ, NULL, 0);
    printf("IORING_REGISTER_ZCRX_IFQ: %d (errno: %d - %s)\n", ret, errno, 
           errno == 14 ? "EFAULT (expected)" : 
           errno == 22 ? "EINVAL" : 
           errno == 95 ? "EOPNOTSUPP" : "other");
    
    // Test unified interface
    ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_UNIFIED_IFQ, NULL, 0);
    printf("IORING_REGISTER_UNIFIED_IFQ: %d (errno: %d - %s)\n", ret, errno,
           errno == 14 ? "EFAULT (expected)" : 
           errno == 22 ? "EINVAL" : 
           errno == 95 ? "EOPNOTSUPP" : "other");
    
    close(ring_fd);
    return 0;
}
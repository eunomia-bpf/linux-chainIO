#include <stdio.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <unistd.h>
#include <errno.h>

int main() {
    int ring_fd;
    struct io_uring_params params = {0};
    
    printf("Testing known working io_uring operations...\n");
    
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }
    
    printf("io_uring setup successful, fd: %d\n", ring_fd);
    
    // Test a known working operation (probe)
    struct io_uring_probe probe;
    int ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_PROBE, &probe, 256);
    printf("IORING_REGISTER_PROBE: %d (errno: %d)\n", ret, errno);
    
    // Test ZCRX interface (should exist)
    ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_ZCRX_IFQ, NULL, 0);
    printf("IORING_REGISTER_ZCRX_IFQ: %d (errno: %d)\n", ret, errno);
    
    // Test unified interface
    ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_UNIFIED_IFQ, NULL, 0);
    printf("IORING_REGISTER_UNIFIED_IFQ: %d (errno: %d)\n", ret, errno);
    
    close(ring_fd);
    return 0;
}
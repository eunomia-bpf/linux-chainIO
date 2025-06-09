#include <stdio.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <unistd.h>
#include <errno.h>

int main() {
    int ring_fd;
    struct io_uring_params params = {0};
    
    printf("Testing basic io_uring setup...\n");
    
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }
    
    printf("io_uring setup successful, fd: %d\n", ring_fd);
    
    // Test if IORING_REGISTER_UNIFIED_IFQ exists
    int ret = syscall(__NR_io_uring_register, ring_fd, 33, NULL, 0);
    printf("IORING_REGISTER_UNIFIED_IFQ test: %d (errno: %d)\n", ret, errno);
    
    close(ring_fd);
    return 0;
}
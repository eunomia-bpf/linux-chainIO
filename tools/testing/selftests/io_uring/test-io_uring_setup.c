#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include "../../../../include/uapi/linux/io_uring.h"

int main()
{
    struct io_uring_params params;
    int ring_fd;
    
    printf("Testing io_uring_setup syscall...\n");
    
    /* Test 1: Basic setup */
    memset(&params, 0, sizeof(params));
    params.flags = 0;
    
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        printf("io_uring_setup failed: %s (errno: %d)\n", strerror(errno), errno);
        return 1;
    }
    
    printf("io_uring_setup succeeded, fd: %d\n", ring_fd);
    close(ring_fd);
    
    /* Test 2: With flags */
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32 | IORING_SETUP_SQE128;
    
    ring_fd = syscall(__NR_io_uring_setup, 256, &params);
    if (ring_fd < 0) {
        printf("io_uring_setup with flags failed: %s (errno: %d)\n", strerror(errno), errno);
    } else {
        printf("io_uring_setup with flags succeeded, fd: %d\n", ring_fd);
        close(ring_fd);
    }
    
    return 0;
}
==============================
NVMe Ring I/O Kernel Module
==============================

Overview
========

The NVMe Ring I/O module provides an AF_XDP-style ring buffer interface
integrated with io_uring fixed buffers for high-performance NVMe passthrough
operations. This enables zero-copy I/O operations to NVMe devices.

Architecture
============

The module combines several key technologies:

1. **AF_XDP-style Ring Buffers**: Shared memory rings between kernel and
   userspace with separate producer/consumer indices for submission and
   completion queues.

2. **io_uring Fixed Buffers**: The ring buffer memory is registered as
   io_uring fixed buffers to avoid repeated pinning/unpinning operations.

3. **NVMe Passthrough**: Direct NVMe command submission using the
   IORING_OP_URING_CMD operation with NVME_URING_CMD_IO.

Memory Layout
=============

The shared memory region has the following layout::

    +------------------+ 0x0000
    | SQ Producer      |
    | SQ Consumer      |
    | CQ Producer      |
    | CQ Consumer      |
    +------------------+ 0x1000 (4KB)
    | SQ Descriptors   |
    | (64-bit addrs)   |
    +------------------+
    | CQ Descriptors   |
    | (64-bit addrs)   |
    +------------------+
    | Data Area        |
    | (Commands/Data)  |
    +------------------+

Building the Module
===================

1. Enable the module in kernel configuration::

    CONFIG_NVME_RING_IO=m

2. Build the kernel module::

    make M=drivers/block modules

3. Load the module::

    sudo insmod drivers/block/nvme_ring_io.ko

Using the Module
================

1. The module creates a character device at ``/dev/nvme_ring_io``

2. Basic usage flow:

   a. Open the device::

        int ring_fd = open("/dev/nvme_ring_io", O_RDWR);

   b. Setup io_uring with 128-byte SQEs::

        struct io_uring ring;
        io_uring_queue_init(256, &ring, 
            IORING_SETUP_SQE128 | IORING_SETUP_CQE32);

   c. Initialize the ring buffer::

        struct nvme_ring_setup setup = {
            .sq_entries = 256,
            .cq_entries = 256,
            .data_size = 4 * 1024 * 1024,
            .nvme_fd = nvme_fd,
            .uring_fd = ring.ring_fd,
        };
        ioctl(ring_fd, NVME_RING_IO_SETUP, &setup);

   d. Map the shared memory::

        void *addr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, ring_fd, 0);

   e. Submit NVMe commands by:
      
      - Writing command to data area
      - Updating SQ descriptor with command address
      - Calling submit ioctl

   f. Process completions::

        struct nvme_ring_complete complete;
        ioctl(ring_fd, NVME_RING_IO_COMPLETE, &complete);

IOCTLs
======

NVME_RING_IO_SETUP
    Initialize the ring buffer with specified sizes and file descriptors.

NVME_RING_IO_SUBMIT
    Submit commands from the ring buffer to NVMe device.

NVME_RING_IO_COMPLETE
    Process completions from NVMe device.

NVME_RING_IO_GET_INFO
    Get current ring buffer statistics.

Sample Program
==============

A sample program is provided in ``samples/nvme_ring_io/`` that demonstrates:

- Ring buffer initialization
- NVMe read command submission
- Completion processing
- Statistics retrieval

Build the sample::

    cd samples/nvme_ring_io
    make

Run the sample::

    sudo ./nvme_ring_io_test /dev/nvme0n1

Performance Considerations
==========================

1. **Memory Allocation**: The module tries to use huge pages when possible
   for better TLB efficiency.

2. **CPU Affinity**: For best performance, bind the application to specific
   CPUs and use NUMA-aware memory allocation.

3. **Polling**: Consider using io_uring polling modes (IOPOLL/SQPOLL) for
   lowest latency.

4. **Batch Operations**: Submit and complete multiple operations at once
   to amortize system call overhead.

Limitations
===========

1. Currently supports only NVMe passthrough commands
2. Requires Linux kernel 5.19+ for IORING_OP_URING_CMD support
3. The io_uring integration requires proper kernel APIs (simplified in example)

Future Work
===========

1. Full io_uring kernel API integration
2. Support for metadata buffers
3. Multi-queue support
4. Enhanced error handling
5. Performance optimizations
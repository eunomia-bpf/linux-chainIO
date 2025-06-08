=======================
io_uring Unified I/O
=======================

Overview
========

The io_uring unified I/O region is a native io_uring feature that combines
network (ZCRX), storage (NVMe), and BPF processing capabilities in a single
shared memory region. This enables true zero-copy data movement between
different I/O subsystems.

Key Features
============

1. **Single Memory Region**: All I/O operations share the same memory region,
   eliminating data copies between subsystems.

2. **AF_XDP Style Rings**: Uses producer/consumer ring buffers similar to
   AF_XDP for efficient descriptor management.

3. **ZCRX Integration**: Compatible with zero-copy receive (ZCRX) through
   net_iov structures and memory provider operations.

4. **NVMe Passthrough**: Direct NVMe command submission without intermediate
   buffers.

5. **BPF Processing**: In-place data processing with attached BPF programs.

Architecture
============

Memory Layout
-------------

The unified region consists of:

- **Control Area** (4KB): Ring indices, statistics, configuration
- **SQ Descriptors**: Submission queue descriptors
- **CQ Descriptors**: Completion queue descriptors  
- **Data Area**: Shared buffer space for all I/O operations

Registration
------------

Register a unified region using ``IORING_REGISTER_UNIFIED_REGION``::

    struct io_uring_unified_region_reg reg = {
        .sq_entries = 256,
        .cq_entries = 256,
        .region_size = 16 * 1024 * 1024,  /* 16MB */
        .nvme_fd = nvme_fd,               /* Optional */
        .net_ifindex = if_nametoindex("eth0"),  /* Optional */
        .net_rxq = 0,
        .region_ptr = &region_desc,
    };
    
    io_uring_register(ring_fd, IORING_REGISTER_UNIFIED_REGION, &reg, 1);

The region can then be mapped using mmap::

    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                     ring_fd, IORING_MAP_OFF_UNIFIED_REGION);

Operations
----------

Submit unified operations using the ``IORING_OP_UNIFIED`` opcode::

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    sqe->opcode = IORING_OP_UNIFIED;
    sqe->off = IORING_UNIFIED_OP_NVME;  /* Operation type */
    sqe->addr = data_offset;             /* Offset in region */
    sqe->len = data_len;                 /* Data length */

Operation types can be combined:

- ``IORING_UNIFIED_OP_NVME``: NVMe passthrough operation
- ``IORING_UNIFIED_OP_NETWORK``: Network packet operation
- ``IORING_UNIFIED_OP_BPF``: BPF processing operation

Use Cases
=========

1. **Network to Storage Pipeline**::

    Network RX → ZCRX → BPF filtering → NVMe write
    
   All operations happen in the same memory without copies.

2. **Storage to Network Pipeline**::

    NVMe read → BPF transform → Network TX
    
   Data flows from storage to network without intermediate buffers.

3. **In-Memory Processing**::

    Network RX → BPF processing → Application
    
   Process network data in-place before application consumption.

Example Code
============

Basic example of using unified I/O::

    #include <liburing.h>
    
    /* Setup io_uring and unified region */
    struct io_uring ring;
    io_uring_queue_init(256, &ring, 0);
    
    /* Register unified region */
    struct io_uring_unified_region_reg reg = { ... };
    io_uring_register(ring.ring_fd, IORING_REGISTER_UNIFIED_REGION, 
                      &reg, 1);
    
    /* Map region */
    void *region = mmap(NULL, reg.region_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, ring.ring_fd, 
                        IORING_MAP_OFF_UNIFIED_REGION);
    
    /* Submit operation */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    sqe->opcode = IORING_OP_UNIFIED;
    sqe->off = IORING_UNIFIED_OP_NVME | IORING_UNIFIED_OP_BPF;
    sqe->addr = data_offset;
    sqe->len = 4096;
    
    io_uring_submit(&ring);

Implementation Status
====================

This is a proof-of-concept implementation demonstrating how unified I/O
could be integrated directly into io_uring. The implementation includes:

- Core infrastructure in ``io_uring/unified.c``
- Registration via ``IORING_REGISTER_UNIFIED_REGION``
- New opcode ``IORING_OP_UNIFIED``
- Integration with existing io_uring infrastructure

Future work would include:

- Full ZCRX integration with page pool
- Complete NVMe passthrough implementation
- BPF program execution framework
- Performance optimizations
- Extended error handling

See Also
========

- :doc:`/networking/af_xdp`
- :doc:`/block/nvme-passthrough`
- :doc:`/bpf/index`
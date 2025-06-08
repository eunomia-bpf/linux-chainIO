==============================================================
io_uring Unified AF_XDP Style NVMe Passthrough Interface
==============================================================

Overview
========

The unified AF_XDP style NVMe passthrough interface combines the benefits of 
BPF zcrx (zero-copy receive) regions with NVMe storage operations in a single
memory-mapped area. This allows for efficient, zero-copy data transfers 
between network reception and storage operations.

Key Features
============

- **Single Memory Region**: Combines ring buffers and data buffers in one mmap area
- **AF_XDP Style Rings**: Uses producer/consumer ring semantics like AF_XDP
- **Zero-Copy Operations**: Direct DMA to/from shared buffers
- **NVMe Passthrough**: Full access to NVMe command set
- **BPF Integration**: Compatible with existing BPF zcrx infrastructure

Memory Layout
=============

The unified memory region has the following layout::

    +-------------------+  <- Base address
    | SQ Ring (4KB)     |  (Submission Queue ring metadata)
    +-------------------+
    | CQ Ring (4KB)     |  (Completion Queue ring metadata)  
    +-------------------+
    | SQ Entries        |  (Submission Queue entries)
    | (N * 128 bytes)   |
    +-------------------+
    | CQ Entries        |  (Completion Queue entries)
    | (N * 64 bytes)    |
    +-------------------+
    | Data Buffers      |  (Actual data buffers for I/O)
    | (M * buffer_size) |
    +-------------------+

Ring Structures
===============

Submission Queue Ring
---------------------

The submission queue ring follows AF_XDP semantics::

    struct io_unified_ring {
        __u32 producer;         /* Producer index (kernel updates) */
        __u32 consumer;         /* Consumer index (userspace updates) */  
        __u32 cached_producer;  /* Cached producer for batching */
        __u32 cached_consumer;  /* Cached consumer for batching */
        __u32 flags;           /* Ring flags */
        __u32 ring_entries;    /* Number of ring entries */
        __u64 ring_mask;       /* Ring mask (entries - 1) */
        __u64 ring_size;       /* Ring size in bytes */
    };

Submission Queue Entry
----------------------

Each submission contains a full NVMe command::

    struct io_unified_sqe {
        struct nvme_uring_cmd nvme_cmd;  /* Standard NVMe uring command */
        __u64 buf_offset;                /* Offset into buffer area */
        __u64 user_data;                 /* User correlation data */
        __u32 flags;                     /* Entry flags */
        __u32 __pad;                     /* Padding */
    };

Completion Queue Entry  
----------------------

Completions provide full NVMe status information::

    struct io_unified_cqe {
        __u64 user_data;    /* Matches sqe user_data */
        __s32 result;       /* NVMe command result */
        __u32 status;       /* NVMe status code */
        __u64 dma_addr;     /* DMA address for zero-copy */
        __u32 len;          /* Data length transferred */
        __u32 flags;        /* Completion flags */
    };

Registration Interface
======================

The unified interface is registered via io_uring_register()::

    struct io_unified_reg {
        __u64 region_ptr;           /* Pointer to region descriptor */
        __u64 nvme_dev_path;        /* Path to NVMe device */
        __u32 sq_entries;           /* Number of SQ entries */
        __u32 cq_entries;           /* Number of CQ entries */
        __u32 buffer_entries;       /* Number of buffer entries */
        __u32 buffer_entry_size;    /* Size of each buffer */
        __u32 flags;                /* Registration flags */
        __u32 __resv[3];            /* Reserved fields */
        
        /* Output: offsets into mapped region */
        struct {
            __u64 sq_ring;      /* Offset to SQ ring */
            __u64 cq_ring;      /* Offset to CQ ring */
            __u64 sq_entries;   /* Offset to SQ entries */
            __u64 cq_entries;   /* Offset to CQ entries */
            __u64 buffers;      /* Offset to buffer area */
        } offsets;
    };

Usage Example
=============

Basic usage pattern::

    /* Create io_uring with required flags */
    struct io_uring_params params = {
        .flags = IORING_SETUP_DEFER_TASKRUN | 
                 IORING_SETUP_CQE32 | 
                 IORING_SETUP_SQE128
    };
    int ring_fd = io_uring_setup(256, &params);
    
    /* Allocate unified memory region */
    size_t total_size = calculate_region_size(sq_entries, cq_entries, 
                                              buffer_entries, buffer_size);
    void *region = mmap(NULL, total_size, PROT_READ|PROT_WRITE,
                        MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    
    /* Set up registration */
    struct io_uring_region_desc rd = {
        .user_addr = (uintptr_t)region,
        .size = total_size
    };
    
    struct io_unified_reg reg = {
        .region_ptr = (uintptr_t)&rd,
        .nvme_dev_path = (uintptr_t)"/dev/nvme0n1",
        .sq_entries = 256,
        .cq_entries = 256,
        .buffer_entries = 1024,
        .buffer_entry_size = 4096
    };
    
    /* Register unified interface */
    io_uring_register(ring_fd, IORING_REGISTER_UNIFIED_IFQ, &reg, 1);
    
    /* Map ring structures using returned offsets */
    struct io_unified_ring *sq_ring = region + reg.offsets.sq_ring;
    struct io_unified_ring *cq_ring = region + reg.offsets.cq_ring;
    struct io_unified_sqe *sq_entries = region + reg.offsets.sq_entries;
    struct io_unified_cqe *cq_entries = region + reg.offsets.cq_entries;
    void *buffers = region + reg.offsets.buffers;

Submitting Commands
===================

Commands are submitted using AF_XDP style producer/consumer semantics::

    /* Get next SQ entry */
    u32 sq_tail = sq_ring->producer;
    struct io_unified_sqe *sqe = &sq_entries[sq_tail & sq_ring->ring_mask];
    
    /* Fill NVMe command */
    sqe->nvme_cmd.opcode = NVME_CMD_READ;
    sqe->nvme_cmd.nsid = 1;
    sqe->nvme_cmd.addr = (uintptr_t)(buffers + buffer_offset);
    sqe->nvme_cmd.data_len = 4096;
    sqe->nvme_cmd.cdw10 = start_lba_low;
    sqe->nvme_cmd.cdw11 = start_lba_high;
    sqe->nvme_cmd.cdw12 = 0;  /* 1 block */
    
    sqe->buf_offset = buffer_offset;
    sqe->user_data = correlation_id;
    
    /* Submit command */
    sq_ring->producer = sq_tail + 1;
    smp_wmb();  /* Memory barrier */

Processing Completions
======================

Completions are processed by polling the completion queue::

    /* Check for completions */
    u32 cq_head = cq_ring->consumer;
    if (cq_ring->producer != cq_head) {
        struct io_unified_cqe *cqe = &cq_entries[cq_head & cq_ring->ring_mask];
        
        /* Process completion */
        if (cqe->status == 0) {
            /* Success - data is in buffer at cqe->dma_addr */
            process_data(buffers + cqe->dma_addr, cqe->len);
        } else {
            /* Error - check cqe->status for NVMe status code */
            handle_error(cqe->status, cqe->result);
        }
        
        /* Mark completion as consumed */
        cq_ring->consumer = cq_head + 1;
        smp_wmb();
    }

Integration with BPF ZCRX
=========================

The unified interface seamlessly integrates with BPF zcrx for network-to-storage
zero-copy operations::

    /* Network data received via BPF zcrx into shared buffer */
    struct net_iov *niov = get_received_packet();
    u32 buffer_id = net_iov_to_buffer_id(niov);
    
    /* Submit NVMe write using the same buffer */
    struct io_unified_sqe *sqe = get_next_sqe();
    sqe->nvme_cmd.opcode = NVME_CMD_WRITE;
    sqe->nvme_cmd.addr = (uintptr_t)get_buffer_addr(buffer_id);
    sqe->buf_offset = buffer_id * buffer_size;
    
    /* Data flows: Network -> Buffer -> NVMe with zero copies */

Configuration
=============

Kernel Configuration
--------------------

Enable the following config options::

    CONFIG_IO_URING=y
    CONFIG_IO_URING_ZCRX=y  
    CONFIG_IO_URING_UNIFIED=y
    CONFIG_NVME_CORE=y

The unified interface requires:

- ``IORING_SETUP_DEFER_TASKRUN`` - For efficient task work
- ``IORING_SETUP_CQE32`` - For extended completion entries  
- ``IORING_SETUP_SQE128`` - For extended submission entries
- ``CAP_SYS_ADMIN`` - For NVMe device access

Performance Considerations
==========================

Buffer Management
-----------------

- Use hugepages for the unified region when possible
- Align buffer entries to page boundaries
- Consider NUMA topology when allocating memory

Ring Sizing
-----------

- Size rings as power of 2 for efficient masking
- Balance ring size vs memory usage
- Consider NVMe queue depth limits

Zero-Copy Optimization
----------------------

- Minimize buffer copies between network and storage
- Use DMA-coherent memory when available
- Batch operations for better throughput

Error Handling
==============

The interface provides comprehensive error reporting:

- **Registration errors**: Standard errno codes
- **NVMe command errors**: Full NVMe status codes in completion entries
- **Memory errors**: EFAULT for invalid addresses
- **Resource errors**: ENOMEM for allocation failures

Common error patterns::

    /* Check registration */
    if (io_uring_register(...) < 0) {
        switch (errno) {
        case EPERM:   /* Need CAP_SYS_ADMIN */
        case EBUSY:   /* Interface already registered */
        case EINVAL:  /* Invalid parameters */
        case ENOMEM:  /* Out of memory */
        }
    }
    
    /* Check command completion */
    if (cqe->status != 0) {
        u16 status_code = cqe->status & 0x7FF;
        u16 status_type = (cqe->status >> 11) & 0x7;
        /* Handle NVMe-specific error codes */
    }

Limitations
===========

Current limitations of the unified interface:

- Single NVMe device per interface instance
- Fixed buffer sizes (no variable-length buffers)
- No support for NVMe metadata
- Limited to data path operations (no admin commands)

Future Enhancements
===================

Planned improvements:

- Multiple device support
- Variable buffer sizes  
- NVMe namespace management
- Advanced error injection
- Performance monitoring integration

See Also
========

- :doc:`/io_uring/io_uring`
- :doc:`/networking/af_xdp` 
- :doc:`/block/nvme`
- :doc:`/bpf/index`
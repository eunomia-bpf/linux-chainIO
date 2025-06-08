===================================
Unified I/O Region Kernel Module
===================================

Overview
========

The Unified I/O Region module provides a single shared memory region that can be
operated by multiple I/O subsystems:

- **Network Stack**: via Zero-Copy RX (ZCRX) with net_iov
- **Storage**: via NVMe passthrough commands  
- **BPF Programs**: for custom data processing

This enables true zero-copy data movement between network, storage, and
compute operations within a single memory region.

Architecture
============

Memory Layout
-------------

The unified region uses a carefully designed memory layout::

    +------------------------+ 0x0000
    | Control Area (4KB)     |
    |   - Ring indices       |
    |   - Statistics         |
    |   - Configuration      |
    +------------------------+ 0x1000
    | Descriptor Area        |
    |   - SQ descriptors     |
    |   - CQ descriptors     |
    |   - Network IOVs       |
    |   - Freelists          |
    |   - Reference counts   |
    +------------------------+
    | Data Area              |
    |   - Shared buffers     |
    |   - Can contain:       |
    |     * NVMe commands    |
    |     * Network packets  |
    |     * Application data |
    +------------------------+

Key Components
--------------

1. **Control Area**: Contains producer/consumer indices for submission and
   completion queues, statistics counters, and configuration flags.

2. **Descriptor Area**: Unified descriptors that can represent different
   operation types (NVMe, network, BPF) with type-specific metadata.

3. **Network IOV Area**: Compatible with ZCRX's net_iov structure for
   zero-copy network receive operations.

4. **Data Area**: The actual data buffers that are shared between all
   subsystems. Data never needs to be copied between subsystems.

Integration Points
==================

ZCRX Integration
----------------

The module implements the memory_provider_ops interface::

    static const struct memory_provider_ops unified_pp_ops = {
        .alloc_netmems = unified_pp_alloc_netmems,
        .release_netmem = unified_pp_release_netmem,
        .init = unified_pp_init,
        .destroy = unified_pp_destroy,
    };

This allows the network stack to allocate buffers directly from the unified
region for zero-copy receive operations.

io_uring Integration
--------------------

The region is registered as an io_uring fixed buffer to avoid repeated
pinning/unpinning operations. NVMe passthrough commands are submitted via
IORING_OP_URING_CMD with the data already in the fixed buffer.

BPF Integration
---------------

BPF programs can be attached to process data in-place within the unified
region. The BPF context provides::

    struct unified_bpf_ctx {
        struct unified_io_region *region;
        struct unified_descriptor *desc;
        void *data;
        u32 data_len;
    };

Usage Examples
==============

Setup
-----

1. Open the device and create the unified region::

    int fd = open("/dev/unified_io_region", O_RDWR);
    
    struct unified_io_setup setup = {
        .sq_entries = 256,
        .cq_entries = 256,
        .region_size = 16 * 1024 * 1024,  // 16MB
        .nvme_fd = nvme_fd,
        .uring_fd = uring_fd,
        .net_ifindex = if_nametoindex("eth0"),
        .net_rxq = 0,
    };
    
    ioctl(fd, UNIFIED_IO_SETUP, &setup);

2. Map the region to userspace::

    void *region = mmap(NULL, setup.region_size, 
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);

3. Attach a BPF program (optional)::

    struct unified_io_bpf bpf_cfg = {
        .prog_fd = bpf_prog_fd,
        .flags = 0,
    };
    ioctl(fd, UNIFIED_IO_ATTACH_BPF, &bpf_cfg);

Submitting Operations
---------------------

All operations use unified descriptors::

    struct unified_descriptor desc = {
        .addr = offset_in_data_area,
        .len = data_length,
        .type = UNIFIED_REGION_F_NVME,  // or _NETWORK, _BPF
        .flags = UNIFIED_DESC_F_READ,
        // ... type-specific fields ...
    };
    
    struct unified_io_submit submit = { .desc = desc };
    ioctl(fd, UNIFIED_IO_SUBMIT, &submit);

Processing Completions
----------------------

Completions are processed in batches::

    struct unified_io_complete complete;
    ioctl(fd, UNIFIED_IO_COMPLETE, &complete);
    // complete.count contains number of completed operations

Use Cases
=========

1. **Network-to-Storage Pipeline**
   
   - Receive network packets directly into unified region via ZCRX
   - Process with BPF program (e.g., extract data, validate)
   - Write to NVMe storage without copying

2. **Storage-to-Network Pipeline**
   
   - Read data from NVMe into unified region
   - Transform with BPF program (e.g., compress, encrypt)
   - Send over network without copying

3. **In-Memory Processing**
   
   - Use unified region as high-performance shared memory
   - Process with multiple BPF programs in sequence
   - Minimal overhead for data movement

Performance Considerations
==========================

1. **Memory Allocation**: The module attempts to use huge pages for better
   TLB efficiency.

2. **CPU Affinity**: Bind operations to specific CPUs to minimize cache
   bouncing.

3. **Batch Operations**: Submit and complete multiple operations together
   to amortize system call overhead.

4. **Ring Sizing**: Choose power-of-2 ring sizes for efficient indexing.

5. **NUMA Awareness**: Allocate memory on the NUMA node closest to the
   NIC and NVMe device.

Debugging
=========

Enable debug output::

    echo 8 > /proc/sys/kernel/printk

Check statistics::

    struct unified_io_info info;
    ioctl(fd, UNIFIED_IO_GET_INFO, &info);

Monitor with ftrace::

    echo unified_submit_operation > /sys/kernel/debug/tracing/set_ftrace_filter
    echo function > /sys/kernel/debug/tracing/current_tracer

Limitations
===========

1. Currently supports a single unified region per file descriptor
2. BPF programs must be carefully written to avoid buffer overruns
3. Network integration requires capable hardware and driver support
4. Maximum region size limited by system memory and huge page availability

Future Work
===========

- Multiple regions per context
- Direct NVMe CMB (Controller Memory Buffer) integration  
- RDMA support for remote memory access
- Hardware offload for BPF programs
- Integration with io_uring's new ring-mapped buffers

References
==========

- io_uring: https://kernel.dk/io_uring.pdf
- ZCRX patches: https://lore.kernel.org/netdev/
- AF_XDP: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
- NVMe specification: https://nvmexpress.org/
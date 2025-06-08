===============================================================
Complete Full-Stack Example: NVMe + NIC + AF_XDP + eBPF
===============================================================

Overview
========

This document describes a complete full-stack implementation that demonstrates
the unified AF_XDP style NVMe passthrough interface working together with:

- **eBPF/XDP**: Kernel-space packet filtering and processing
- **AF_XDP**: Zero-copy network packet access
- **io_uring Unified Interface**: Combined zcrx and NVMe operations
- **NVMe Storage**: High-speed SSD storage

The result is a complete zero-copy data path from network reception to persistent
storage, with all data processing happening in shared memory buffers.

Architecture
============

Data Flow
---------

The complete data flow follows this path::

    Network Packets
         ↓
    [eBPF/XDP Program]
         ↓ (filter UDP port 9999)
    [AF_XDP Socket]
         ↓ (zero-copy to userspace)
    [Unified Buffer Region]
         ↓ (packet processing)
    [NVMe Submission Queue]
         ↓ (async I/O)
    [NVMe SSD Storage]

Memory Layout
-------------

The unified memory region serves multiple purposes::

    +------------------+
    | SQ Ring          | ← io_uring submission queue metadata
    +------------------+
    | CQ Ring          | ← io_uring completion queue metadata  
    +------------------+
    | SQ Entries       | ← NVMe command entries
    +------------------+
    | CQ Entries       | ← NVMe completion entries
    +------------------+
    | Data Buffers     | ← Shared between AF_XDP and NVMe
    |                  |   • AF_XDP UMEM frames
    |                  |   • NVMe I/O buffers
    |                  |   • Zero-copy data path
    +------------------+

Components
==========

eBPF/XDP Program
----------------

The XDP program performs several functions:

1. **Packet Filtering**: Only processes UDP packets on port 9999
2. **Metadata Extraction**: Captures source/destination IP and ports
3. **Event Logging**: Sends packet info to userspace via ring buffer
4. **Zero-Copy Redirect**: Forwards packets to AF_XDP socket

Key features of the XDP program:

.. code-block:: c

    /* Filter for storage traffic */
    if (udp->dest != bpf_htons(9999))
        return XDP_PASS;
    
    /* Log packet metadata */
    info = bpf_ringbuf_reserve(&events, sizeof(*info), 0);
    if (info) {
        info->src_ip = ip->saddr;
        info->dst_ip = ip->daddr;
        info->payload_len = payload_len;
        info->timestamp = bpf_ktime_get_ns();
        bpf_ringbuf_submit(info, 0);
    }
    
    /* Redirect to AF_XDP for zero-copy processing */
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

AF_XDP Integration
------------------

AF_XDP provides zero-copy packet access by sharing memory with the unified region:

.. code-block:: c

    /* UMEM area points to unified data buffers */
    umem_area = ctx.data_buffers;
    
    /* Configure UMEM to use unified buffers */
    umem_cfg.frame_size = FRAME_SIZE;
    umem_cfg.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
    
    ret = xsk_umem__create(&ctx.umem, umem_area, NUM_FRAMES * FRAME_SIZE,
                           &ctx.fq, &ctx.cq, &umem_cfg);

Packet Processing
-----------------

The userspace application processes packets in batches:

.. code-block:: c

    /* Receive batch of packets */
    ret = xsk_ring_cons__peek(&ctx.rx, RX_BATCH_SIZE, &idx_rx);
    
    for (int i = 0; i < ret; i++) {
        __u64 addr = xsk_ring_cons__rx_desc(&ctx.rx, idx_rx)->addr;
        __u32 len = xsk_ring_cons__rx_desc(&ctx.rx, idx_rx)->len;
        
        void *pkt_data = (char *)ctx.data_buffers + addr;
        
        /* Extract packet payload */
        void *payload = extract_udp_payload(pkt_data, len);
        
        /* Submit directly to NVMe using same buffer */
        submit_storage_write(payload, storage_len, next_lba, correlation_id);
    }

NVMe Storage Integration
------------------------

Storage operations use the same buffers as network reception:

.. code-block:: c

    /* Get SQ entry */
    sqe = &ctx.sq_entries[sq_tail & ctx.sq_ring->ring_mask];
    
    /* Fill NVMe write command */
    sqe->nvme_cmd.opcode = 0x01;  /* Write */
    sqe->nvme_cmd.nsid = 1;       /* Namespace 1 */
    sqe->nvme_cmd.addr = (__u64)(uintptr_t)data;  /* Same buffer! */
    sqe->nvme_cmd.data_len = len;
    sqe->nvme_cmd.cdw10 = (__u32)(lba & 0xFFFFFFFF);
    sqe->nvme_cmd.cdw11 = (__u32)(lba >> 32);
    
    /* Submit to hardware */
    ctx.sq_ring->producer = sq_tail + 1;

Threading Model
===============

The application uses a multi-threaded design for optimal performance:

Main Thread
-----------
- Program initialization
- Statistics reporting
- Cleanup and shutdown

Packet Processing Thread
------------------------
- AF_XDP packet reception
- Packet parsing and metadata extraction
- NVMe command submission
- Buffer management

Storage Completion Thread
-------------------------
- NVMe completion processing  
- Buffer recycling
- Error handling
- Performance monitoring

Building and Running
====================

Prerequisites
-------------

Install required dependencies:

.. code-block:: bash

    # Ubuntu/Debian
    sudo apt-get install clang libbpf-dev libxdp-dev libelf-dev
    
    # RHEL/Fedora  
    sudo dnf install clang libbpf-devel libxdp-devel elfutils-libelf-devel

Building
--------

.. code-block:: bash

    cd tools/testing/selftests/io_uring
    make -f Makefile.full-stack

Running the Test
----------------

.. code-block:: bash

    # Run with defaults
    sudo ./run-full-stack-test.sh
    
    # Specify interface and device
    sudo ./run-full-stack-test.sh eth0 /dev/nvme0n1 0
    
    # The script will:
    # 1. Check system requirements
    # 2. Build the test program
    # 3. Set up the network interface
    # 4. Start the unified interface
    # 5. Generate test traffic
    # 6. Show real-time statistics

Example Output
--------------

.. code-block:: text

    [INFO] Full-Stack Unified Interface Test
    [INFO] Checking system requirements...
    [SUCCESS] System requirements check passed
    [INFO] Setting up network interface 'eth0'...
    [SUCCESS] Interface setup complete
    [INFO] Building test program...
    [SUCCESS] Test program built successfully
    [INFO] Starting full-stack test...
    [INFO] Interface: eth0 (queue 0)
    [INFO] NVMe device: /dev/nvme0n1
    [INFO] Listening port: 9999
    
    BPF program loaded successfully
    AF_XDP socket created on eth0 queue 0
    Unified interface registered successfully
      SQ ring: 0x7f8b4c000000 (entries: 256)
      CQ ring: 0x7f8b4c001000 (entries: 256) 
      Data buffers: 0x7f8b4c008000
    
    Packet processing thread started
    Storage thread started
    System ready. Waiting for packets...
    
    Stats: RX=1247 pps=52 | Stored=1245 Bps=5177344 | Errors=0

Performance Characteristics
===========================

Zero-Copy Benefits
------------------

The unified interface eliminates multiple copy operations:

**Traditional Path**::

    Network → Driver → Kernel Buffer → User Buffer → Kernel Buffer → Storage
    (3 copies, multiple context switches)

**Unified Interface Path**::

    Network → Shared Buffer → Storage
    (0 copies, minimal context switches)

Latency Improvements
--------------------

Typical latency breakdown:

- **Network to AF_XDP**: ~1-2μs (hardware dependent)
- **Packet Processing**: ~0.5μs (parsing UDP header)
- **NVMe Submission**: ~0.1μs (ring operation)
- **Storage Completion**: ~100μs (NVMe device dependent)

Throughput Scaling
------------------

The system scales with:

- **Network Interface Speed**: 10Gbps+ with appropriate NICs
- **NVMe Performance**: Limited by SSD write bandwidth
- **CPU Cores**: Packet processing can use multiple queues
- **Memory Bandwidth**: Unified buffers reduce memory pressure

Configuration Tuning
=====================

Network Interface
-----------------

Optimize for XDP performance:

.. code-block:: bash

    # Disable features that interfere with XDP
    ethtool -K eth0 gro off lro off tso off
    
    # Increase ring buffer sizes
    ethtool -G eth0 rx 4096 tx 4096
    
    # Set multi-queue if supported
    ethtool -L eth0 combined 4

Memory Configuration
--------------------

Use hugepages for better performance:

.. code-block:: bash

    # Reserve hugepages
    echo 1024 > /proc/sys/vm/nr_hugepages
    
    # Mount hugepage filesystem
    mount -t hugetlbfs hugetlbfs /mnt/hugepages

NVMe Optimization
-----------------

Configure NVMe for low latency:

.. code-block:: bash

    # Set I/O scheduler to none for NVMe
    echo none > /sys/block/nvme0n1/queue/scheduler
    
    # Increase queue depth
    echo 32 > /sys/block/nvme0n1/queue/nr_requests

Monitoring and Debugging
=========================

eBPF Program Status
-------------------

.. code-block:: bash

    # Show loaded XDP programs
    bpftool net show
    
    # Dump program instructions
    bpftool prog dump xlated id <prog_id>
    
    # Show map contents
    bpftool map dump id <map_id>

AF_XDP Statistics
-----------------

.. code-block:: bash

    # Show socket statistics
    ss -A xdp -p
    
    # Interface XDP statistics
    ip -s link show eth0

NVMe Performance
----------------

.. code-block:: bash

    # Monitor I/O statistics
    iostat -x 1 nvme0n1
    
    # Show NVMe device info
    nvme list
    nvme id-ctrl /dev/nvme0n1

Common Issues and Solutions
===========================

XDP Program Not Loading
------------------------

**Issue**: XDP program fails to attach

**Solutions**:
- Ensure driver supports XDP in native mode
- Check for sufficient permissions (CAP_SYS_ADMIN)
- Verify BPF filesystem is mounted
- Use SKB mode as fallback: ``XDP_FLAGS_SKB_MODE``

AF_XDP Socket Creation Fails
-----------------------------

**Issue**: Cannot create AF_XDP socket

**Solutions**:
- Increase RLIMIT_MEMLOCK: ``ulimit -l unlimited``
- Check kernel CONFIG_XDP_SOCKETS=y
- Ensure interface is up and has queues available
- Try different queue ID if multi-queue

NVMe Operations Fail
--------------------

**Issue**: Storage writes return errors

**Solutions**:
- Verify device permissions and access rights
- Check namespace ID (usually 1 for first namespace)
- Ensure LBA addresses are within device capacity
- Validate data alignment (512-byte boundaries)

Performance Bottlenecks
-----------------------

**Issue**: Lower than expected throughput

**Solutions**:
- Check CPU affinity and NUMA placement
- Monitor for packet drops in XDP statistics
- Increase buffer sizes and queue depths
- Verify hardware offload features are configured

Use Cases
=========

Real-Time Analytics
-------------------

Process streaming data and store results:

- Market data ingestion and storage
- IoT sensor data collection
- Network monitoring and logging

High-Performance Caching
-------------------------

Network-attached storage cache:

- Content delivery network (CDN) edge nodes
- Database write-through cache
- Distributed storage systems

Data Pipeline Acceleration
---------------------------

Zero-copy data processing:

- ETL (Extract, Transform, Load) pipelines
- Real-time data warehousing
- Stream processing frameworks

Limitations and Future Work
===========================

Current Limitations
-------------------

- Single NVMe device per interface instance
- Fixed buffer sizes (no dynamic allocation)
- UDP-only traffic filtering in example
- Limited error recovery mechanisms

Future Enhancements
-------------------

- Multi-device support with load balancing
- Dynamic buffer pool management
- TCP/other protocol support
- Advanced error handling and recovery
- Performance monitoring integration
- Container/virtualization support

Conclusion
==========

This full-stack example demonstrates the power of combining modern Linux
kernel technologies to achieve true zero-copy data paths. By integrating
eBPF/XDP, AF_XDP, and the unified io_uring interface, applications can
achieve unprecedented performance for network-to-storage operations.

The unified approach eliminates traditional performance bottlenecks and
enables new classes of high-performance applications that require minimal
latency and maximum throughput between network and storage subsystems.

See Also
========

- :doc:`/io_uring/unified-nvme-interface`
- :doc:`/networking/af_xdp`
- :doc:`/bpf/index` 
- :doc:`/block/nvme`
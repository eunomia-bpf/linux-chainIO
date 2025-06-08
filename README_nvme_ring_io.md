# NVMe Ring I/O - AF_XDP Style Ring Buffer with io_uring Integration

## Overview

This project implements a Linux kernel module that combines AF_XDP-style ring buffers with io_uring fixed buffer registration to enable high-performance, zero-copy NVMe passthrough operations.

## Key Features

- **AF_XDP-style ring buffers**: Shared memory rings between kernel and userspace
- **io_uring integration**: Fixed buffer registration to avoid pin/unpin overhead
- **NVMe passthrough**: Direct command submission using IORING_OP_URING_CMD
- **Zero-copy I/O**: Data stays in the same memory region throughout the I/O path
- **High performance**: Designed for minimal latency and maximum throughput

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   User Space    │     │   Kernel Space  │
├─────────────────┤     ├─────────────────┤
│                 │     │                 │
│  Application    │     │  nvme_ring_io   │
│       ↓         │     │       ↓         │
│  Ring Buffer    │<--->│  Ring Buffer    │
│  (mmap'd)       │     │  (shared)       │
│       ↓         │     │       ↓         │
│   io_uring      │     │   io_uring      │
│                 │     │       ↓         │
│                 │     │  NVMe Driver    │
│                 │     │       ↓         │
└─────────────────┘     └───────┴─────────┘
                                │
                                ↓
                         ┌──────────────┐
                         │  NVMe Device │
                         └──────────────┘
```

## Files Structure

```
linux-chainIO/
├── drivers/block/
│   ├── nvme_ring_io.c      # Main kernel module
│   ├── Kconfig             # Configuration options
│   └── Makefile            # Build rules
├── include/uapi/linux/
│   └── nvme_ring_io.h      # User-kernel interface definitions
├── samples/nvme_ring_io/
│   ├── nvme_ring_io_test.c # Sample application
│   └── Makefile            # Sample build rules
├── Documentation/block/
│   └── nvme-ring-io.rst    # Detailed documentation
└── scripts/
    └── nvme_ring_io_setup.sh # Setup and build script
```

## Quick Start

### Prerequisites

- Linux kernel 5.19+ (for IORING_OP_URING_CMD support)
- NVMe device
- liburing development package
- Root privileges for module loading

### Build and Install

```bash
# Run the setup script (requires root)
sudo ./scripts/nvme_ring_io_setup.sh
```

This script will:
1. Build the kernel module
2. Load the module
3. Create the device node `/dev/nvme_ring_io`
4. Build the sample program

### Run Sample Program

```bash
# Test with your NVMe device
sudo ./samples/nvme_ring_io/nvme_ring_io_test /dev/nvme0n1
```

## Programming Guide

### Basic Usage Flow

1. **Open the device**
   ```c
   int ring_fd = open("/dev/nvme_ring_io", O_RDWR);
   ```

2. **Setup io_uring**
   ```c
   struct io_uring ring;
   io_uring_queue_init(256, &ring, IORING_SETUP_SQE128 | IORING_SETUP_CQE32);
   ```

3. **Initialize ring buffer**
   ```c
   struct nvme_ring_setup setup = {
       .sq_entries = 256,
       .cq_entries = 256,
       .data_size = 4 * 1024 * 1024,
       .nvme_fd = nvme_fd,
       .uring_fd = ring.ring_fd,
   };
   ioctl(ring_fd, NVME_RING_IO_SETUP, &setup);
   ```

4. **Map shared memory**
   ```c
   void *addr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, ring_fd, 0);
   ```

5. **Submit commands**
   - Write NVMe command to data area
   - Update SQ descriptor
   - Call submit ioctl

6. **Process completions**
   ```c
   struct nvme_ring_complete complete;
   ioctl(ring_fd, NVME_RING_IO_COMPLETE, &complete);
   ```

## Memory Layout

```
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
```

## Performance Tips

1. **Use huge pages**: The module attempts to allocate huge pages for better TLB efficiency
2. **CPU affinity**: Bind your application to specific CPUs
3. **Batch operations**: Submit/complete multiple operations at once
4. **Polling modes**: Consider io_uring IOPOLL/SQPOLL for lowest latency

## Current Limitations

1. Simplified io_uring integration (requires full kernel API integration)
2. Basic error handling
3. Single queue support only
4. No metadata buffer support yet

## Future Enhancements

- Full io_uring kernel API integration
- Multi-queue support
- Metadata buffer support
- Enhanced error handling and recovery
- Performance optimizations
- Support for more NVMe command types

## Troubleshooting

### Module won't load
- Check kernel version (5.19+ required)
- Verify CONFIG_NVME_CORE and CONFIG_IO_URING are enabled
- Check dmesg for error messages

### Device node not created
- Verify module loaded: `lsmod | grep nvme_ring_io`
- Check device class: `ls /sys/class/nvme_ring_io_class/`

### Sample program fails
- Ensure you have an NVMe device
- Run with sudo for device access
- Check that liburing is installed

## License

This project is licensed under GPL-2.0.

## Contributing

Contributions are welcome! Areas of interest:
- Performance improvements
- Additional NVMe command support
- Better error handling
- Documentation improvements

## References

- [io_uring documentation](https://kernel.dk/io_uring.pdf)
- [NVMe specification](https://nvmexpress.org/specifications/)
- [AF_XDP documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
# Unified I/O Region - Zero-Copy Integration of Network, Storage, and BPF

## Project Overview

This project implements a Linux kernel module that creates a **unified memory region** capable of being operated by:
- **Network stack** (via ZCRX - Zero-Copy Receive)
- **Storage system** (via NVMe passthrough)  
- **BPF programs** (for custom data processing)

The key innovation is that data never needs to be copied between these subsystems - they all operate on the same shared memory region.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              User Space Application              │
├─────────────────────────────────────────────────┤
│                  mmap() region                   │
├─────────────────────────────────────────────────┤
│            Unified I/O Region Module             │
├─────────┬──────────────┬───────────────┬────────┤
│  ZCRX   │   io_uring   │     BPF      │  Ring  │
│ net_iov │ fixed buffer │   context    │ Buffer │
├─────────┴──────────────┴───────────────┴────────┤
│              Shared Memory Region                │
│  ┌──────────┬──────────┬──────────┬──────────┐ │
│  │ Control  │ Descs    │ Net IOVs │   Data   │ │
│  │  Area    │ (SQ/CQ)  │ (ZCRX)   │   Area   │ │
│  └──────────┴──────────┴──────────┴──────────┘ │
├─────────┬──────────────┬───────────────┬────────┤
│   NIC   │    NVMe      │   Network     │  BPF   │
│ Driver  │   Driver     │    Stack     │  VM    │
└─────────┴──────────────┴───────────────┴────────┘
```

## Key Features

### 1. Unified Memory Management
- Single memory allocation shared across all I/O subsystems
- AF_XDP-style ring buffers for submission/completion
- Compatible with ZCRX's net_iov structure
- Supports huge pages for better performance

### 2. Zero-Copy Operations
- Network packets received directly into unified buffer
- NVMe commands operate on same memory
- BPF programs process data in-place
- No data copying between subsystems

### 3. Flexible Operation Types
- **NVMe**: Read/Write/Flush operations via passthrough
- **Network**: TCP/UDP/Raw packet processing
- **BPF**: Custom data transformations and filtering

## Building and Installation

### Prerequisites
- Linux kernel 5.19+ (for IORING_OP_URING_CMD support)
- io_uring library (liburing-dev)
- BPF development tools (libbpf-dev, clang)
- NVMe device (optional)
- Network interface with ZCRX support (optional)

### Build Steps

1. **Configure kernel options**:
   ```bash
   CONFIG_UNIFIED_IO_REGION=m
   CONFIG_NVME_CORE=y
   CONFIG_IO_URING=y
   CONFIG_NET=y
   CONFIG_BPF_SYSCALL=y
   CONFIG_PAGE_POOL=y
   ```

2. **Build the module**:
   ```bash
   make M=drivers/block modules
   ```

3. **Load the module**:
   ```bash
   sudo insmod drivers/block/unified_io_region.ko
   ```

4. **Build sample application**:
   ```bash
   cd samples/unified_io
   make
   ```

## Usage Example

```c
// 1. Setup unified region
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

// 2. Map the region
void *region = mmap(NULL, setup.region_size, 
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);

// 3. Submit operations
struct unified_descriptor desc = {
    .addr = 0,        // Offset in data area
    .len = 4096,      // Data length
    .type = UNIFIED_REGION_F_NVME | UNIFIED_REGION_F_BPF,
    .nvme.opcode = NVME_CMD_READ,
    .nvme.nsid = 1,
};

struct unified_io_submit submit = { .desc = desc };
ioctl(fd, UNIFIED_IO_SUBMIT, &submit);

// 4. Process completions
struct unified_io_complete complete;
ioctl(fd, UNIFIED_IO_COMPLETE, &complete);
```

## Use Cases

### 1. Network-to-Storage Pipeline
```
Network → ZCRX → BPF Processing → NVMe Write
```
- Receive data packets via ZCRX
- Process/filter with BPF
- Write directly to NVMe SSD
- **Zero copies throughout**

### 2. Storage-to-Network Pipeline  
```
NVMe Read → BPF Transform → Network Send
```
- Read data from NVMe SSD
- Transform data with BPF (compress/encrypt)
- Send over network
- **All in same memory region**

### 3. In-Memory Database
```
Network Request → BPF Query → NVMe Persist → Network Response
```
- Process queries in BPF
- Persist to NVMe when needed
- Respond to network clients
- **Minimal latency**

## Performance Tips

1. **Use huge pages**: Better TLB efficiency
2. **CPU affinity**: Pin to specific cores
3. **Batch operations**: Submit/complete multiple ops together
4. **NUMA awareness**: Allocate near devices
5. **Ring sizing**: Use power-of-2 sizes

## Project Structure

```
linux-chainIO/
├── drivers/block/
│   ├── unified_io_region.c     # Main kernel module
│   ├── nvme_ring_io.c          # Original NVMe ring implementation
│   ├── Kconfig                 # Configuration options
│   └── Makefile                # Build rules
├── include/uapi/linux/
│   ├── unified_io_region.h     # Unified I/O interface
│   └── nvme_ring_io.h          # NVMe ring interface
├── samples/
│   ├── unified_io/
│   │   ├── unified_io_test.c   # Unified I/O demo
│   │   └── Makefile
│   └── nvme_ring_io/
│       ├── nvme_ring_io_test.c # NVMe ring demo
│       └── Makefile
└── Documentation/block/
    ├── unified-io-region.rst   # Unified I/O docs
    └── nvme-ring-io.rst        # NVMe ring docs
```

## Comparison with Existing Approaches

| Feature | Traditional | AF_XDP | io_uring | **Unified I/O** |
|---------|------------|---------|----------|-----------------|
| Zero-copy Network | ❌ | ✅ | ❌ | ✅ |
| Zero-copy Storage | ❌ | ❌ | ✅ | ✅ |
| BPF Integration | Limited | ✅ | ❌ | ✅ |
| Cross-subsystem | ❌ | ❌ | ❌ | ✅ |
| Single Memory Region | ❌ | ❌ | ❌ | ✅ |

## Current Limitations

1. Single region per file descriptor
2. Requires capable hardware for ZCRX
3. BPF programs must be carefully written
4. Limited to available system memory

## Future Enhancements

- [ ] Multiple regions per context
- [ ] Direct NVMe CMB integration
- [ ] RDMA support
- [ ] Hardware BPF offload
- [ ] Persistent memory support
- [ ] Multi-queue scaling

## Contributing

Contributions are welcome! Key areas:
- Performance optimizations
- Additional device support
- Enhanced BPF helpers
- Testing and benchmarks

## References

- [io_uring documentation](https://kernel.dk/io_uring.pdf)
- [ZCRX patches](https://lore.kernel.org/netdev/)
- [AF_XDP guide](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [NVMe specification](https://nvmexpress.org/)
- [BPF documentation](https://docs.kernel.org/bpf/)

## License

GPL-2.0

---

This project demonstrates the future of zero-copy I/O in Linux, where network, storage, and compute can seamlessly share memory regions for maximum performance.
#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Script to build and load the Unified I/O Region kernel module
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Unified I/O Region Module Setup Script"
echo "======================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Check dependencies
echo "Checking dependencies..."
deps=("make" "gcc" "clang")
for dep in "${deps[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo "ERROR: $dep is not installed"
        exit 1
    fi
done

# Check for required libraries
echo "Checking libraries..."
if ! pkg-config --exists libbpf; then
    echo "ERROR: libbpf is not installed"
    echo "Install with: apt-get install libbpf-dev"
    exit 1
fi

if ! pkg-config --exists liburing; then
    echo "ERROR: liburing is not installed"
    echo "Install with: apt-get install liburing-dev"
    exit 1
fi

# Build the modules
echo "Building kernel modules..."
cd "${KERNEL_DIR}"
make M=drivers/block CONFIG_NVME_RING_IO=m CONFIG_UNIFIED_IO_REGION=m modules

if [ ! -f "drivers/block/nvme_ring_io.ko" ]; then
    echo "ERROR: Failed to build nvme_ring_io.ko"
    exit 1
fi

if [ ! -f "drivers/block/unified_io_region.ko" ]; then
    echo "ERROR: Failed to build unified_io_region.ko"
    exit 1
fi

# Unload modules if already loaded
echo "Checking for loaded modules..."
if lsmod | grep -q unified_io_region; then
    echo "Unloading existing unified_io_region module..."
    rmmod unified_io_region
fi

if lsmod | grep -q nvme_ring_io; then
    echo "Unloading existing nvme_ring_io module..."
    rmmod nvme_ring_io
fi

# Load the modules
echo "Loading nvme_ring_io module..."
insmod drivers/block/nvme_ring_io.ko

echo "Loading unified_io_region module..."
insmod drivers/block/unified_io_region.ko

# Check if modules loaded successfully
if ! lsmod | grep -q nvme_ring_io; then
    echo "ERROR: Failed to load nvme_ring_io module"
    exit 1
fi

if ! lsmod | grep -q unified_io_region; then
    echo "ERROR: Failed to load unified_io_region module"
    exit 1
fi

# Check if device nodes were created
if [ ! -c /dev/nvme_ring_io ]; then
    echo "ERROR: Device node /dev/nvme_ring_io was not created"
    exit 1
fi

if [ ! -c /dev/unified_io_region ]; then
    echo "ERROR: Device node /dev/unified_io_region was not created"
    exit 1
fi

# Set permissions
echo "Setting device permissions..."
chmod 666 /dev/nvme_ring_io
chmod 666 /dev/unified_io_region

# Build sample programs
echo "Building sample programs..."
cd "${KERNEL_DIR}/samples/nvme_ring_io"
make

cd "${KERNEL_DIR}/samples/unified_io"
make

echo ""
echo "Setup completed successfully!"
echo ""
echo "Module information:"
echo "==================="
modinfo drivers/block/nvme_ring_io.ko
echo ""
modinfo drivers/block/unified_io_region.ko
echo ""
echo "Device nodes:"
echo "============="
echo "  /dev/nvme_ring_io      - NVMe ring I/O device"
echo "  /dev/unified_io_region - Unified I/O region device"
echo ""
echo "Sample programs:"
echo "================"
echo "  samples/nvme_ring_io/nvme_ring_io_test"
echo "  samples/unified_io/unified_io_test"
echo ""
echo "To test NVMe ring I/O:"
echo "  sudo ./samples/nvme_ring_io/nvme_ring_io_test /dev/nvme0n1"
echo ""
echo "To test unified I/O region:"
echo "  sudo ./samples/unified_io/unified_io_test /dev/nvme0n1 eth0"
echo ""
echo "To unload the modules:"
echo "  sudo rmmod unified_io_region"
echo "  sudo rmmod nvme_ring_io"
echo ""
echo "To check statistics:"
echo "  cat /proc/modules | grep -E 'nvme_ring_io|unified_io_region'"
echo "  dmesg | tail -20"
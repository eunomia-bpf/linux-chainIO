#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Script to build and load the NVMe Ring I/O kernel module
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "NVMe Ring I/O Module Setup Script"
echo "================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Check dependencies
echo "Checking dependencies..."
if ! command -v make &> /dev/null; then
    echo "ERROR: make is not installed"
    exit 1
fi

# Build the module
echo "Building kernel module..."
cd "${KERNEL_DIR}"
make M=drivers/block CONFIG_NVME_RING_IO=m modules

if [ ! -f "drivers/block/nvme_ring_io.ko" ]; then
    echo "ERROR: Failed to build nvme_ring_io.ko"
    exit 1
fi

# Unload module if already loaded
if lsmod | grep -q nvme_ring_io; then
    echo "Unloading existing nvme_ring_io module..."
    rmmod nvme_ring_io
fi

# Load the module
echo "Loading nvme_ring_io module..."
insmod drivers/block/nvme_ring_io.ko

# Check if module loaded successfully
if ! lsmod | grep -q nvme_ring_io; then
    echo "ERROR: Failed to load nvme_ring_io module"
    exit 1
fi

# Check if device node was created
if [ ! -c /dev/nvme_ring_io ]; then
    echo "ERROR: Device node /dev/nvme_ring_io was not created"
    exit 1
fi

# Set permissions
echo "Setting device permissions..."
chmod 666 /dev/nvme_ring_io

# Build sample program
echo "Building sample program..."
cd "${KERNEL_DIR}/samples/nvme_ring_io"
make

echo ""
echo "Setup completed successfully!"
echo ""
echo "Module information:"
modinfo drivers/block/nvme_ring_io.ko
echo ""
echo "Device node: /dev/nvme_ring_io"
echo "Sample program: samples/nvme_ring_io/nvme_ring_io_test"
echo ""
echo "To test the module, run:"
echo "  sudo ./samples/nvme_ring_io/nvme_ring_io_test /dev/nvme0n1"
echo ""
echo "To unload the module, run:"
echo "  sudo rmmod nvme_ring_io"
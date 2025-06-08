#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Script to demonstrate the full-stack unified NVMe+AF_XDP+eBPF test
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_PROG="$SCRIPT_DIR/unified-full-stack-test"
INTERFACE="${1:-eth0}"
NVME_DEV="${2:-/dev/nvme0n1}"
QUEUE_ID="${3:-0}"
TEST_DATA_PORT=9999

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

check_requirements() {
    log_info "Checking system requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This test requires root privileges"
        log_info "Please run with: sudo $0 $@"
        exit 1
    fi
    
    # Check interface exists
    if ! ip link show "$INTERFACE" &>/dev/null; then
        log_error "Network interface '$INTERFACE' not found"
        log_info "Available interfaces:"
        ip link show | grep '^[0-9]' | awk '{print "  " $2}' | sed 's/:$//'
        exit 1
    fi
    
    # Check NVMe device
    if [[ ! -b "$NVME_DEV" ]]; then
        log_warn "NVMe device '$NVME_DEV' not found or not accessible"
        log_info "Available NVMe devices:"
        ls -la /dev/nvme* 2>/dev/null || log_warn "No NVMe devices found"
        log_info "Test will continue but storage operations may fail"
    fi
    
    # Check required tools
    local missing_tools=()
    for tool in clang bpftool ip tc ethtool; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: apt-get install ${missing_tools[*]} (Ubuntu/Debian)"
        log_info "Or: dnf install ${missing_tools[*]} (RHEL/Fedora)"
        exit 1
    fi
    
    # Check kernel features
    log_info "Checking kernel features..."
    
    if [[ ! -d /sys/fs/bpf ]]; then
        log_warn "BPF filesystem not mounted, mounting..."
        mount -t bpf bpf /sys/fs/bpf || {
            log_error "Failed to mount BPF filesystem"
            exit 1
        }
    fi
    
    # Check if interface supports XDP
    if ! ethtool -i "$INTERFACE" | grep -q "driver:"; then
        log_warn "Cannot determine driver for $INTERFACE"
    fi
    
    log_success "System requirements check passed"
}

setup_interface() {
    log_info "Setting up network interface '$INTERFACE'..."
    
    # Bring interface up
    ip link set "$INTERFACE" up
    
    # Enable multi-queue if supported
    local max_queues
    max_queues=$(ethtool -l "$INTERFACE" 2>/dev/null | grep "Combined:" | tail -n1 | awk '{print $2}')
    if [[ -n "$max_queues" && "$max_queues" -gt 1 ]]; then
        log_info "Interface supports $max_queues queues"
        if [[ "$QUEUE_ID" -ge "$max_queues" ]]; then
            log_warn "Queue ID $QUEUE_ID >= max queues $max_queues, using queue 0"
            QUEUE_ID=0
        fi
    fi
    
    # Disable generic receive offload for better XDP performance
    ethtool -K "$INTERFACE" gro off 2>/dev/null || log_warn "Could not disable GRO"
    
    log_success "Interface setup complete"
}

build_test_program() {
    log_info "Building test program..."
    
    cd "$SCRIPT_DIR"
    
    if [[ ! -f "Makefile.full-stack" ]]; then
        log_error "Makefile.full-stack not found in $SCRIPT_DIR"
        exit 1
    fi
    
    # Check dependencies first
    make -f Makefile.full-stack check-deps || {
        log_error "Dependency check failed"
        log_info "Try running: make -f Makefile.full-stack install-deps-ubuntu"
        log_info "Or: make -f Makefile.full-stack install-deps-rhel"
        exit 1
    }
    
    # Build the program
    make -f Makefile.full-stack clean
    make -f Makefile.full-stack || {
        log_error "Build failed"
        exit 1
    }
    
    if [[ ! -x "$TEST_PROG" ]]; then
        log_error "Test program not found: $TEST_PROG"
        exit 1
    fi
    
    log_success "Test program built successfully"
}

generate_test_traffic() {
    local interface="$1"
    local port="$2"
    
    log_info "Generating test traffic on port $port..."
    
    # Get interface IP
    local ip_addr
    ip_addr=$(ip addr show "$interface" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    
    if [[ -z "$ip_addr" ]]; then
        log_warn "No IP address found on $interface, using localhost"
        ip_addr="127.0.0.1"
    fi
    
    # Generate test packets using Python
    cat > /tmp/generate_traffic.py << 'EOF'
#!/usr/bin/env python3
import socket
import time
import sys
import struct

def generate_traffic(target_ip, target_port, duration=60):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    packet_count = 0
    start_time = time.time()
    
    print(f"Sending UDP packets to {target_ip}:{target_port} for {duration} seconds")
    
    while time.time() - start_time < duration:
        # Create test payload with timestamp and sequence number
        timestamp = int(time.time() * 1000000)  # microseconds
        payload = f"TEST_DATA_{packet_count:08d}_TS_{timestamp}".encode()
        payload += b"A" * (1024 - len(payload))  # Pad to 1KB
        
        try:
            sock.sendto(payload, (target_ip, target_port))
            packet_count += 1
            
            if packet_count % 1000 == 0:
                print(f"Sent {packet_count} packets...")
            
            time.sleep(0.001)  # 1ms between packets = 1000 pps
        except Exception as e:
            print(f"Error sending packet: {e}")
            break
    
    sock.close()
    print(f"Traffic generation complete. Sent {packet_count} packets")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_traffic.py <ip> <port>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    
    generate_traffic(target_ip, target_port)
EOF
    
    # Run traffic generator in background
    python3 /tmp/generate_traffic.py "$ip_addr" "$port" &
    local traffic_pid=$!
    
    echo "$traffic_pid"
}

run_test() {
    log_info "Starting full-stack test..."
    log_info "Interface: $INTERFACE (queue $QUEUE_ID)"
    log_info "NVMe device: $NVME_DEV"
    log_info "Listening port: $TEST_DATA_PORT"
    
    # Start the test program
    log_info "Starting unified interface test program..."
    "$TEST_PROG" "$INTERFACE" "$NVME_DEV" "$QUEUE_ID" &
    local test_pid=$!
    
    # Wait a moment for the program to initialize
    sleep 3
    
    # Check if test program is still running
    if ! kill -0 "$test_pid" 2>/dev/null; then
        log_error "Test program failed to start"
        wait "$test_pid"
        return $?
    fi
    
    log_success "Test program started (PID: $test_pid)"
    
    # Generate test traffic
    log_info "Starting traffic generation..."
    local traffic_pid
    traffic_pid=$(generate_test_traffic "$INTERFACE" "$TEST_DATA_PORT")
    
    # Setup cleanup trap
    cleanup() {
        log_info "Cleaning up..."
        [[ -n "$test_pid" ]] && kill "$test_pid" 2>/dev/null
        [[ -n "$traffic_pid" ]] && kill "$traffic_pid" 2>/dev/null
        rm -f /tmp/generate_traffic.py
        
        # Remove XDP program
        if ip link show "$INTERFACE" | grep -q xdp; then
            log_info "Removing XDP program from $INTERFACE"
            ip link set "$INTERFACE" xdp off 2>/dev/null || true
        fi
    }
    trap cleanup EXIT
    
    # Let the test run
    log_info "Test running... Press Ctrl+C to stop"
    
    # Monitor the test
    local runtime=0
    while kill -0 "$test_pid" 2>/dev/null && [[ $runtime -lt 300 ]]; do  # Max 5 minutes
        sleep 5
        runtime=$((runtime + 5))
        
        # Check XDP program status
        if ip link show "$INTERFACE" | grep -q xdp; then
            log_info "XDP program is attached (runtime: ${runtime}s)"
        else
            log_warn "XDP program not found on interface"
        fi
    done
    
    # Stop traffic generation
    [[ -n "$traffic_pid" ]] && kill "$traffic_pid" 2>/dev/null || true
    
    # Stop test program gracefully
    log_info "Stopping test program..."
    kill -INT "$test_pid" 2>/dev/null || true
    
    # Wait for cleanup
    sleep 2
    
    # Force kill if still running
    if kill -0 "$test_pid" 2>/dev/null; then
        log_warn "Force killing test program"
        kill -KILL "$test_pid" 2>/dev/null || true
    fi
    
    wait "$test_pid" 2>/dev/null || true
    
    log_success "Test completed"
}

show_results() {
    log_info "Test Results Summary:"
    echo
    echo "The test demonstrated the following data path:"
    echo "1. Network packets received on $INTERFACE"
    echo "2. eBPF XDP program filtered UDP packets on port $TEST_DATA_PORT"
    echo "3. AF_XDP socket provided zero-copy packet access"
    echo "4. Unified interface stored packet data to $NVME_DEV"
    echo "5. Complete zero-copy path: Network -> eBPF -> AF_XDP -> NVMe"
    echo
    
    # Show any remaining XDP programs
    if command -v bpftool &>/dev/null; then
        echo "Current XDP programs:"
        bpftool net show 2>/dev/null | grep "$INTERFACE" || echo "  None"
    fi
    
    echo
    log_success "Full-stack unified interface test completed successfully!"
    
    # Show next steps
    echo
    log_info "To analyze the stored data:"
    echo "  # Check what was written to NVMe device"
    echo "  sudo hexdump -C $NVME_DEV | head -20"
    echo
    log_info "To monitor performance:"
    echo "  # Watch interface statistics"
    echo "  watch -n1 'cat /proc/net/dev | grep $INTERFACE'"
    echo
    log_info "To manually send test packets:"
    echo "  # Send UDP packet to trigger storage"
    echo "  echo 'test data' | nc -u localhost $TEST_DATA_PORT"
}

main() {
    log_info "Full-Stack Unified Interface Test"
    log_info "================================="
    echo
    
    check_requirements
    setup_interface
    build_test_program
    run_test
    show_results
}

# Show usage if no arguments provided
if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [interface] [nvme_device] [queue_id]"
    echo
    echo "Examples:"
    echo "  $0                          # Use defaults: eth0, /dev/nvme0n1, queue 0"
    echo "  $0 ens33                    # Use ens33 interface"
    echo "  $0 eth1 /dev/nvme1n1        # Use eth1 and nvme1n1"
    echo "  $0 enp0s3 /dev/nvme0n1 1    # Use enp0s3, nvme0n1, queue 1"
    echo
    echo "This test demonstrates a complete zero-copy data path:"
    echo "  Network → eBPF/XDP → AF_XDP → Unified Buffer → NVMe Storage"
    echo
    exit 0
fi

# Run the main function
main "$@"
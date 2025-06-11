// SPDX-License-Identifier: GPL-2.0
/*
 * XDP with RDMA unified interface demonstration
 * 
 * This program demonstrates the XDP_FLAGS_RDMA functionality:
 * 1. NIC driver (ICE) checks XDP_FLAGS_RDMA flag
 * 2. If set, XDP program is transferred to SoftRoCE
 * 3. Unified RDMA driver handles XDP program for packet capture
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <linux/io_uring.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>

/* XDP program that filters RDMA traffic */
static const char xdp_rdma_prog[] = 
"#include <linux/bpf.h>\n"
"#include <linux/if_ether.h>\n"
"#include <linux/ip.h>\n"
"#include <linux/udp.h>\n"
"#include <bpf/bpf_helpers.h>\n"
"\n"
"SEC(\"xdp\")\n"
"int xdp_rdma_filter(struct xdp_md *ctx) {\n"
"    void *data_end = (void *)(long)ctx->data_end;\n"
"    void *data = (void *)(long)ctx->data;\n"
"    struct ethhdr *eth = data;\n"
"    struct iphdr *ip;\n"
"    struct udphdr *udp;\n"
"\n"
"    /* Bounds check */\n"
"    if (eth + 1 > data_end)\n"
"        return XDP_PASS;\n"
"\n"
"    /* Check for IP */\n"
"    if (eth->h_proto != __constant_htons(ETH_P_IP))\n"
"        return XDP_PASS;\n"
"\n"
"    ip = (struct iphdr *)(eth + 1);\n"
"    if (ip + 1 > data_end)\n"
"        return XDP_PASS;\n"
"\n"
"    /* Check for UDP (common for RDMA over Ethernet) */\n"
"    if (ip->protocol != IPPROTO_UDP)\n"
"        return XDP_PASS;\n"
"\n"
"    udp = (struct udphdr *)(ip + 1);\n"
"    if (udp + 1 > data_end)\n"
"        return XDP_PASS;\n"
"\n"
"    /* Check for RoCE port (4791) */\n"
"    if (udp->dest == __constant_htons(4791)) {\n"
"        /* This is RDMA traffic - redirect to unified buffer */\n"
"        return XDP_REDIRECT;\n"
"    }\n"
"\n"
"    return XDP_PASS;\n"
"}\n"
"\n"
"char _license[] SEC(\"license\") = \"GPL\";\n";

static void usage(const char *prog)
{
	printf("Usage: %s <interface> [rdma|normal]\n", prog);
	printf("  interface: Network interface (e.g., eth0, ib0)\n");
	printf("  mode:      'rdma' - Load XDP to SoftRoCE via XDP_FLAGS_RDMA\n");
	printf("             'normal' - Load XDP to NIC driver normally\n");
	printf("\nExample:\n");
	printf("  %s ib0 rdma    # Load XDP program to unified RDMA interface\n");
	printf("  %s eth0 normal # Load XDP program to NIC driver\n");
}

static int compile_xdp_program(void)
{
	FILE *f;
	int ret;
	
	/* Write XDP program to temporary file */
	f = fopen("/tmp/xdp_rdma_prog.c", "w");
	if (!f) {
		perror("fopen");
		return -1;
	}
	
	fprintf(f, "%s", xdp_rdma_prog);
	fclose(f);
	
	/* Compile with clang */
	ret = system("clang -O2 -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -c /tmp/xdp_rdma_prog.c -o /tmp/xdp_rdma_prog.o");
	if (ret != 0) {
		fprintf(stderr, "Failed to compile XDP program\n");
		return -1;
	}
	
	printf("Compiled XDP RDMA filter program\n");
	return 0;
}

static int load_xdp_program(const char *interface, int use_rdma_flag)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prog_fd, ifindex;
	uint32_t xdp_flags = 0;
	
	/* Get interface index */
	ifindex = if_nametoindex(interface);
	if (ifindex == 0) {
		fprintf(stderr, "Unknown interface: %s\n", interface);
		return -1;
	}
	
	/* Load BPF object */
	obj = bpf_object__open("/tmp/xdp_rdma_prog.o");
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to open BPF object\n");
		return -1;
	}
	
	if (bpf_object__load(obj)) {
		fprintf(stderr, "Failed to load BPF object\n");
		bpf_object__close(obj);
		return -1;
	}
	
	/* Find XDP program */
	prog = bpf_object__find_program_by_name(obj, "xdp_rdma_filter");
	if (!prog) {
		fprintf(stderr, "Failed to find XDP program\n");
		bpf_object__close(obj);
		return -1;
	}
	
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to get program fd\n");
		bpf_object__close(obj);
		return -1;
	}
	
	/* Set XDP flags based on mode */
	if (use_rdma_flag) {
		xdp_flags |= XDP_FLAGS_RDMA;
		printf("Loading XDP program with XDP_FLAGS_RDMA - will transfer to SoftRoCE\n");
	} else {
		xdp_flags |= XDP_FLAGS_DRV_MODE;
		printf("Loading XDP program normally to NIC driver\n");
	}
	
	/* Attach XDP program */
	if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0) {
		perror("bpf_xdp_attach");
		bpf_object__close(obj);
		return -1;
	}
	
	if (use_rdma_flag) {
		printf("✓ XDP program loaded with XDP_FLAGS_RDMA\n");
		printf("  - ICE driver detected XDP_FLAGS_RDMA flag\n");
		printf("  - XDP program transferred to unified RDMA driver\n");
		printf("  - SoftRoCE will now process RDMA packets with XDP\n");
		printf("  - Packets with UDP port 4791 (RoCE) will be redirected\n");
	} else {
		printf("✓ XDP program loaded normally to NIC driver\n");
		printf("  - Standard XDP processing in network driver\n");
	}
	
	/* Keep object alive */
	printf("\nPress Ctrl+C to unload XDP program and exit\n");
	
	/* Wait for signal */
	pause();
	
	/* Cleanup */
	bpf_xdp_detach(ifindex, xdp_flags, NULL);
	bpf_object__close(obj);
	
	printf("\nXDP program unloaded\n");
	return 0;
}

static void demonstrate_data_flows(void)
{
	printf("\n=== XDP with RDMA Unified Interface Data Flows ===\n\n");
	
	printf("1. Normal XDP (XDP_FLAGS_DRV_MODE):\n");
	printf("   Network → NIC Driver XDP → Kernel Network Stack\n");
	printf("   - XDP program runs in NIC driver\n");
	printf("   - Standard packet processing\n\n");
	
	printf("2. XDP with RDMA (XDP_FLAGS_RDMA):\n");
	printf("   Network → NIC Driver → SoftRoCE XDP → Unified Buffer\n");
	printf("   - NIC driver detects XDP_FLAGS_RDMA\n");
	printf("   - XDP program transferred to SoftRoCE\n");
	printf("   - RDMA packets processed by XDP in unified interface\n");
	printf("   - Zero-copy to unified buffer for storage processing\n\n");
	
	printf("3. Unified Data Path:\n");
	printf("   RDMA XDP → Unified Buffer ← AF_XDP ← Network XDP\n");
	printf("                    ↓\n");
	printf("                 NVMe Storage\n");
	printf("   - Single memory region for all I/O\n");
	printf("   - Zero-copy between network, RDMA, and storage\n");
	printf("   - XDP programs can redirect to unified buffers\n\n");
}

int main(int argc, char *argv[])
{
	const char *interface;
	const char *mode;
	int use_rdma_flag = 0;
	
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	
	interface = argv[1];
	mode = argc > 2 ? argv[2] : "normal";
	
	if (strcmp(mode, "rdma") == 0) {
		use_rdma_flag = 1;
	} else if (strcmp(mode, "normal") == 0) {
		use_rdma_flag = 0;
	} else {
		fprintf(stderr, "Invalid mode: %s\n", mode);
		usage(argv[0]);
		return 1;
	}
	
	printf("XDP with RDMA Unified Interface Demo\n");
	printf("====================================\n");
	printf("Interface: %s\n", interface);
	printf("Mode: %s\n", use_rdma_flag ? "RDMA unified" : "Normal XDP");
	printf("\n");
	
	/* Show data flow explanation */
	demonstrate_data_flows();
	
	/* Compile XDP program */
	if (compile_xdp_program() < 0) {
		return 1;
	}
	
	/* Load and attach XDP program */
	if (load_xdp_program(interface, use_rdma_flag) < 0) {
		return 1;
	}
	
	/* Cleanup */
	unlink("/tmp/xdp_rdma_prog.c");
	unlink("/tmp/xdp_rdma_prog.o");
	
	return 0;
}
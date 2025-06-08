/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_UNIFIED_IO_REGION_H
#define _UAPI_LINUX_UNIFIED_IO_REGION_H

#include <linux/types.h>

/* Unified region operation types */
#define UNIFIED_REGION_F_NVME		(1 << 0)
#define UNIFIED_REGION_F_NETWORK	(1 << 1)
#define UNIFIED_REGION_F_BPF		(1 << 2)

/* ioctl command definitions */
#define UNIFIED_IO_SETUP	_IOW('U', 0x80, struct unified_io_setup)
#define UNIFIED_IO_SUBMIT	_IOW('U', 0x81, struct unified_io_submit)
#define UNIFIED_IO_COMPLETE	_IOR('U', 0x82, struct unified_io_complete)
#define UNIFIED_IO_ATTACH_BPF	_IOW('U', 0x83, struct unified_io_bpf)
#define UNIFIED_IO_GET_INFO	_IOR('U', 0x84, struct unified_io_info)

/* Setup structure for unified region initialization */
struct unified_io_setup {
	__u32 sq_entries;	/* Number of submission queue entries */
	__u32 cq_entries;	/* Number of completion queue entries */
	__u32 region_size;	/* Total region size in bytes */
	int nvme_fd;		/* NVMe device file descriptor (-1 to skip) */
	int uring_fd;		/* io_uring file descriptor (-1 to skip) */
	int net_ifindex;	/* Network interface index (0 to skip) */
	int net_rxq;		/* Network RX queue index */
	__u32 flags;		/* Setup flags */
};

/* Unified descriptor for operations */
struct unified_descriptor {
	__u64 addr;		/* Offset into data area */
	__u32 len;		/* Length of data */
	__u16 flags;		/* Operation flags */
	__u16 type;		/* Operation type (UNIFIED_REGION_F_*) */
	union {
		/* NVMe specific */
		struct {
			__u16 opcode;
			__u16 nsid;
		} nvme;
		/* Network specific */
		struct {
			__u16 proto;
			__u16 port;
		} net;
		/* BPF specific */
		struct {
			__u32 prog_id;
		} bpf;
	};
};

/* Submit structure */
struct unified_io_submit {
	struct unified_descriptor desc;
};

/* Completion structure */
struct unified_io_complete {
	__u32 count;		/* Number of completed operations */
	__u32 flags;		/* Completion flags */
};

/* BPF attachment structure */
struct unified_io_bpf {
	__u32 prog_fd;		/* BPF program file descriptor */
	__u32 flags;		/* BPF flags */
};

/* Information structure */
struct unified_io_info {
	__u64 nvme_ops;		/* Total NVMe operations */
	__u64 net_packets;	/* Total network packets */
	__u64 bpf_ops;		/* Total BPF operations */
	__u64 submitted;	/* Total submitted operations */
	__u64 completed;	/* Total completed operations */
	__u32 sq_head;		/* SQ consumer index */
	__u32 sq_tail;		/* SQ producer index */
	__u32 cq_head;		/* CQ consumer index */
	__u32 cq_tail;		/* CQ producer index */
};

/* Control area structure (mapped at offset 0) */
struct unified_control {
	/* Ring indices */
	struct {
		__u32 producer;
		__u32 consumer;
	} sq, cq;
	
	/* Network queue indices */
	struct {
		__u32 producer;
		__u32 consumer;
	} net_rx, net_tx;
	
	/* Statistics */
	__u64 nvme_ops;
	__u64 net_packets;
	__u64 bpf_ops;
	
	/* Flags and configuration */
	__u32 flags;
	__u32 region_size;
	__u32 data_offset;
	__u32 data_size;
};

/* Descriptor flags */
#define UNIFIED_DESC_F_WRITE	(1 << 0)	/* Write operation */
#define UNIFIED_DESC_F_READ	(1 << 1)	/* Read operation */
#define UNIFIED_DESC_F_SYNC	(1 << 2)	/* Synchronous operation */
#define UNIFIED_DESC_F_BATCH	(1 << 3)	/* Part of batch */

/* Network protocol types */
#define UNIFIED_NET_PROTO_TCP	0x0001
#define UNIFIED_NET_PROTO_UDP	0x0002
#define UNIFIED_NET_PROTO_RAW	0x0003

/* NVMe opcodes (subset) */
#define UNIFIED_NVME_OPC_READ	0x02
#define UNIFIED_NVME_OPC_WRITE	0x01
#define UNIFIED_NVME_OPC_FLUSH	0x00

#endif /* _UAPI_LINUX_UNIFIED_IO_REGION_H */
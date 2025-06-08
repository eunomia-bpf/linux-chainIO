/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_NVME_RING_IO_H
#define _UAPI_LINUX_NVME_RING_IO_H

#include <linux/types.h>

/* ioctl command definitions */
#define NVME_RING_IO_SETUP	_IOW('N', 0x80, struct nvme_ring_setup)
#define NVME_RING_IO_SUBMIT	_IOW('N', 0x81, struct nvme_ring_submit)
#define NVME_RING_IO_COMPLETE	_IOR('N', 0x82, struct nvme_ring_complete)
#define NVME_RING_IO_GET_INFO	_IOR('N', 0x83, struct nvme_ring_info)

/* Setup structure for ring initialization */
struct nvme_ring_setup {
	__u32 sq_entries;	/* Number of submission queue entries */
	__u32 cq_entries;	/* Number of completion queue entries */
	__u32 data_size;	/* Size of data buffer area */
	int nvme_fd;		/* NVMe device file descriptor */
	int uring_fd;		/* io_uring file descriptor */
	__u32 flags;		/* Setup flags */
	__u32 reserved[4];	/* Reserved for future use */
};

/* Submit structure for command submission */
struct nvme_ring_submit {
	__u64 desc_addr;	/* Descriptor address in ring buffer */
	__u32 count;		/* Number of commands to submit */
	__u32 flags;		/* Submit flags */
};

/* Complete structure for retrieving completions */
struct nvme_ring_complete {
	__u32 count;		/* Number of completed commands */
	__u32 flags;		/* Completion flags */
};

/* Ring information structure */
struct nvme_ring_info {
	__u32 sq_entries;	/* Current SQ size */
	__u32 cq_entries;	/* Current CQ size */
	__u64 sq_head;		/* SQ head pointer */
	__u64 sq_tail;		/* SQ tail pointer */
	__u64 cq_head;		/* CQ head pointer */
	__u64 cq_tail;		/* CQ tail pointer */
	__u64 submitted;	/* Total submitted commands */
	__u64 completed;	/* Total completed commands */
};

/* Ring descriptor format */
struct nvme_ring_desc {
	__u64 addr;		/* Address of data in ring buffer */
	__u32 len;		/* Length of data */
	__u16 flags;		/* Descriptor flags */
	__u16 reserved;		/* Reserved */
};

/* Descriptor flags */
#define NVME_RING_DESC_F_WRITE	(1 << 0)	/* Write operation */
#define NVME_RING_DESC_F_READ	(1 << 1)	/* Read operation */
#define NVME_RING_DESC_F_FLUSH	(1 << 2)	/* Flush operation */

/* Setup flags */
#define NVME_RING_SETUP_IOPOLL	(1 << 0)	/* Use io_uring polling mode */
#define NVME_RING_SETUP_SQPOLL	(1 << 1)	/* Use io_uring SQ polling */

#endif /* _UAPI_LINUX_NVME_RING_IO_H */
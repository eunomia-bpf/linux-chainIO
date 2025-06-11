/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_IO_URING_UNIFIED_H
#define _UAPI_LINUX_IO_URING_UNIFIED_H

#include <linux/types.h>

/* Unified interface structures for user space */

struct io_unified_reg {
	__u64 region_ptr;		/* pointer to region descriptor */
	__u64 nvme_dev_path;		/* path to nvme device */
	__u32 sq_entries;		/* number of submission queue entries */
	__u32 cq_entries;		/* number of completion queue entries */
	__u32 buffer_entries;		/* number of buffer entries */
	__u32 buffer_entry_size;	/* size of each buffer entry */
	__u32 flags;
	__u32 __resv[3];
	
	/* Output fields */
	struct {
		__u64 sq_ring;		/* offset to SQ ring */
		__u64 cq_ring;		/* offset to CQ ring */
		__u64 sq_entries;	/* offset to SQ entries */
		__u64 cq_entries;	/* offset to CQ entries */
		__u64 buffers;		/* offset to buffer area */
	} offsets;
};

struct io_unified_ring {
	__u32 producer;
	__u32 consumer;
	__u32 cached_producer;
	__u32 cached_consumer;
	__u32 flags;
	__u32 ring_entries;
	__u64 ring_mask;
	__u64 ring_size;
};

struct nvme_uring_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32   rsvd2;
};

struct io_unified_sqe {
	struct nvme_uring_cmd nvme_cmd;
	__u64 buf_offset;	/* offset into unified buffer area */
	__u64 user_data;	/* for correlation with completion */
	__u32 flags;
	__u32 __pad;
};

struct io_unified_cqe {
	__u64 user_data;	/* matches sqe user_data */
	__s32 result;		/* operation result */
	__u32 status;		/* nvme status */
	__u64 dma_addr;		/* dma address of buffer used */
	__u32 len;		/* length of data transferred */
	__u32 flags;
};

#endif /* _UAPI_LINUX_IO_URING_UNIFIED_H */
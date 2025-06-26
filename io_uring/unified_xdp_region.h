// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_UNIFIED_XDP_REGION_H
#define IOU_UNIFIED_XDP_REGION_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <net/xdp.h>
#include <net/xdp_sock.h>

struct io_ring_ctx;
struct net_device;
struct ib_device;

/**
 * enum io_unified_protocol - Supported protocols in unified region
 */
enum io_unified_protocol {
	IO_PROTOCOL_SOCKET = 0,
	IO_PROTOCOL_RDMA,
	IO_PROTOCOL_STORAGE,
	IO_PROTOCOL_MAX
};

/**
 * struct io_unified_buffer_desc - Buffer descriptor for unified region
 * @addr: Virtual address of the buffer
 * @dma_addr: DMA address for device access
 * @size: Buffer size
 * @protocol_mask: Bitmask indicating which protocols can use this buffer
 * @ref_count: Reference count for the buffer
 * @flags: Buffer status flags
 */
struct io_unified_buffer_desc {
	void *addr;
	dma_addr_t dma_addr;
	u32 size;
	u32 protocol_mask;
	atomic_t ref_count;
	u32 flags;
};

/**
 * struct io_unified_xdp_region - Unified memory region for XDP and multiple protocols
 * @base_addr: Base virtual address of the region
 * @dma_base: Base DMA address
 * @total_size: Total size of the region
 * @buffer_size: Size of each individual buffer
 * @buffer_count: Total number of buffers
 * @alignment: Buffer alignment requirement
 * 
 * @buffers: Array of buffer descriptors
 * @free_list: Free buffer management
 * @free_count: Number of free buffers
 * @free_lock: Lock for free list operations
 * 
 * @xdp_umem: XDP user memory area
 * @xdp_frames: XDP frame descriptors
 * @xdp_enabled: XDP functionality enabled
 * 
 * @protocol_queues: Per-protocol queue management
 * @protocol_stats: Per-protocol statistics
 * 
 * @pages: Pinned pages for the region
 * @page_count: Number of pages
 * 
 * @ctx: Associated io_uring context
 * @dev: Network device for XDP
 * @ib_dev: RDMA device
 * 
 * @lock: Main region lock
 * @ref_count: Region reference count
 * @flags: Region flags
 */
struct io_unified_xdp_region {
	/* Memory layout */
	void *base_addr;
	dma_addr_t dma_base;
	size_t total_size;
	u32 buffer_size;
	u32 buffer_count;
	u32 alignment;

	/* Buffer management */
	struct io_unified_buffer_desc *buffers;
	u32 *free_list;
	u32 free_count;
	spinlock_t free_lock;

	/* XDP integration */
	struct xsk_umem *xdp_umem;
	struct xdp_frame **xdp_frames;
	bool xdp_enabled;

	/* Protocol-specific queues */
	struct {
		struct io_uring *ring;
		void *entries;
		u32 head;
		u32 tail;
		u32 mask;
	} protocol_queues[IO_PROTOCOL_MAX];

	/* Statistics */
	struct {
		atomic64_t allocations;
		atomic64_t deallocations;
		atomic64_t xdp_redirects;
		atomic64_t protocol_switches;
	} protocol_stats[IO_PROTOCOL_MAX];

	/* Memory backing */
	struct page **pages;
	u32 page_count;

	/* Device associations */
	struct io_ring_ctx *ctx;
	struct net_device *dev;
	struct ib_device *ib_dev;

	/* Synchronization */
	spinlock_t lock;
	atomic_t ref_count;
	u32 flags;
};

/**
 * struct io_unified_xdp_config - Configuration for unified XDP region
 */
struct io_unified_xdp_config {
	size_t region_size;
	u32 buffer_size;
	u32 buffer_count;
	u32 alignment;
	u32 xdp_headroom;
	u32 protocol_mask;
	u32 flags;

	/* Device identifiers */
	char netdev_name[IFNAMSIZ];
	char rdma_dev_name[64];
};

/* Region flags */
#define IO_UNIFIED_XDP_ZEROCOPY (1U << 0)
#define IO_UNIFIED_XDP_SOCKET (1U << 1)
#define IO_UNIFIED_XDP_RDMA (1U << 2)
#define IO_UNIFIED_XDP_STORAGE (1U << 3)
#define IO_UNIFIED_XDP_NEED_WAKEUP (1U << 4)

/* Buffer flags */
#define IO_BUFFER_FREE (1U << 0)
#define IO_BUFFER_IN_USE (1U << 1)
#define IO_BUFFER_XDP_ATTACHED (1U << 2)
#define IO_BUFFER_DMA_MAPPED (1U << 3)

/* Protocol masks */
#define IO_PROTOCOL_SOCKET_MASK (1U << IO_PROTOCOL_SOCKET)
#define IO_PROTOCOL_RDMA_MASK (1U << IO_PROTOCOL_RDMA)
#define IO_PROTOCOL_STORAGE_MASK (1U << IO_PROTOCOL_STORAGE)
#define IO_PROTOCOL_ALL_MASK ((1U << IO_PROTOCOL_MAX) - 1)

/* Function declarations */

/* Region management */
int io_unified_xdp_region_create(struct io_ring_ctx *ctx,
				 struct io_unified_xdp_config *config,
				 struct io_unified_xdp_region **region);
void io_unified_xdp_region_destroy(struct io_unified_xdp_region *region);

/* Buffer allocation/deallocation */
int io_unified_buffer_alloc(struct io_unified_xdp_region *region,
			    enum io_unified_protocol protocol,
			    struct io_unified_buffer_desc **buffer);
void io_unified_buffer_free(struct io_unified_xdp_region *region,
			    struct io_unified_buffer_desc *buffer);

/* XDP integration */
int io_unified_xdp_attach(struct io_unified_xdp_region *region,
			  struct bpf_prog *prog);
void io_unified_xdp_detach(struct io_unified_xdp_region *region);
int io_unified_xdp_redirect(struct io_unified_xdp_region *region,
			    struct xdp_buff *xdp,
			    enum io_unified_protocol target_protocol);

/* Protocol-specific operations */
int io_unified_socket_setup(struct io_unified_xdp_region *region,
			    struct socket *sock);
int io_unified_rdma_setup(struct io_unified_xdp_region *region,
			  struct ib_device *ib_dev);
int io_unified_storage_setup(struct io_unified_xdp_region *region);

/* Buffer conversions */
int io_unified_buffer_to_xdp(struct io_unified_buffer_desc *buffer,
			     struct xdp_buff *xdp, u32 offset, u32 len);
int io_unified_buffer_to_skb(struct io_unified_buffer_desc *buffer,
			     struct sk_buff **skb, u32 offset, u32 len);
int io_unified_buffer_to_rdma_wr(struct io_unified_buffer_desc *buffer,
				 void *rdma_wr, u32 offset, u32 len);

/* Cross-protocol operations */
int io_unified_protocol_switch(struct io_unified_xdp_region *region,
			       struct io_unified_buffer_desc *buffer,
			       enum io_unified_protocol from_protocol,
			       enum io_unified_protocol to_protocol);

/* Statistics and monitoring */
void io_unified_region_get_stats(struct io_unified_xdp_region *region,
				 struct io_unified_stats *stats);
void io_unified_region_reset_stats(struct io_unified_xdp_region *region);

/* Debug and utilities */
void io_unified_region_dump_state(struct io_unified_xdp_region *region);
bool io_unified_region_is_healthy(struct io_unified_xdp_region *region);

#endif /* IOU_UNIFIED_XDP_REGION_H */
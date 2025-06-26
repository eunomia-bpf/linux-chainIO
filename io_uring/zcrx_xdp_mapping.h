// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZCRX_XDP_MAPPING_H
#define IOU_ZCRX_XDP_MAPPING_H

#include <linux/types.h>
#include <net/xdp.h>

struct io_zcrx_ifq;
struct net_iov;

/**
 * struct io_zcrx_xdp_config - Configuration for XDP mapping
 * @frame_size: Size of each XDP frame
 * @chunk_size: Size of each memory chunk
 * @headroom: Headroom for XDP program modifications
 * @flags: Configuration flags
 */
struct io_zcrx_xdp_config {
	u32 frame_size;
	u32 chunk_size;
	u32 headroom;
	u32 flags;
};

/* XDP mapping flags */
#define IO_ZCRX_XDP_ZEROCOPY (1U << 0)
#define IO_ZCRX_XDP_COPY_MODE (1U << 1)
#define IO_ZCRX_XDP_NEED_WAKEUP (1U << 2)

/* Function declarations */
int io_zcrx_to_xdp_buf(struct net_iov *niov, struct xdp_buff *xdp, u32 offset,
		       u32 len);
int io_zcrx_xdp_buf_to_niov(struct xdp_buff *xdp, struct net_iov **niov);

int io_zcrx_setup_xdp_mapping(struct io_zcrx_ifq *ifq,
			      struct io_zcrx_xdp_config *config);
void io_zcrx_teardown_xdp_mapping(struct io_zcrx_ifq *ifq);

int io_zcrx_xdp_redirect(struct io_zcrx_ifq *ifq, struct xdp_buff *xdp,
			 u32 target_index);

struct xdp_frame *io_zcrx_get_xdp_frame(struct io_zcrx_ifq *ifq, u32 index);
struct sk_buff *io_zcrx_xdp_frame_to_skb(struct io_zcrx_ifq *ifq,
					 u32 frame_index);

#endif /* IOU_ZCRX_XDP_MAPPING_H */
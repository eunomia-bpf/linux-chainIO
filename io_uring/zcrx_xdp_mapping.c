// SPDX-License-Identifier: GPL-2.0
/*
 * Zero-copy RX region to XDP buffer mapping implementation
 *
 * This file implements the mapping between io_uring's zcrx_region
 * and XDP buffers for efficient packet processing.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/io_uring.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_xdp.h>
#include <net/xdp.h>
#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/net_trackers.h>

#include "io_uring.h"
#include "zcrx.h"
#include "memmap.h"

/**
 * struct io_zcrx_xdp_mapping - XDP buffer mapping for zcrx region
 * @zcrx_area: Associated zero-copy RX area
 * @xdp_umem: XDP user memory area
 * @xdp_frames: Array of XDP frame descriptors
 * @frame_count: Number of XDP frames
 * @frame_size: Size of each XDP frame
 * @chunk_size: Size of each memory chunk
 * @headroom: Headroom for XDP program modifications
 * @flags: Mapping flags
 * @lock: Synchronization lock
 */
struct io_zcrx_xdp_mapping {
    struct io_zcrx_area *zcrx_area;
    struct xsk_umem *xdp_umem;
    struct xdp_frame **xdp_frames;
    u32 frame_count;
    u32 frame_size;
    u32 chunk_size;
    u32 headroom;
    u32 flags;
    spinlock_t lock;
};

/**
 * io_zcrx_to_xdp_buf - Convert zcrx net_iov to xdp_buff
 * @niov: Network IOV from zcrx area
 * @xdp: XDP buffer to populate
 * @offset: Offset within the page
 * @len: Length of the data
 */
int io_zcrx_to_xdp_buf(struct net_iov *niov, struct xdp_buff *xdp, 
                       u32 offset, u32 len)
{
    struct io_zcrx_area *area;
    struct page *page;
    void *data;
    
    if (!niov || !xdp)
        return -EINVAL;
        
    area = io_zcrx_iov_to_area(niov);
    if (!area)
        return -EINVAL;
        
    page = io_zcrx_iov_page(niov);
    if (!page)
        return -EINVAL;
    
    /* Map page to virtual address */
    data = page_address(page);
    if (!data)
        return -ENOMEM;
    
    /* Setup XDP buffer */
    xdp->data_hard_start = data;
    xdp->data = data + offset + XDP_PACKET_HEADROOM;
    xdp->data_end = xdp->data + len;
    xdp->data_meta = xdp->data;
    xdp->frame_sz = PAGE_SIZE;
    
    /* Associate with the network IOV for reference counting */
    xdp->netmem = net_iov_to_netmem(niov);
    
    return 0;
}

/**
 * io_zcrx_xdp_buf_to_niov - Convert XDP buffer back to net_iov
 * @xdp: XDP buffer
 * @niov: Network IOV to populate
 */
int io_zcrx_xdp_buf_to_niov(struct xdp_buff *xdp, struct net_iov **niov)
{
    if (!xdp || !niov || !xdp->netmem)
        return -EINVAL;
        
    if (!netmem_is_net_iov(xdp->netmem))
        return -EINVAL;
        
    *niov = netmem_to_net_iov(xdp->netmem);
    return 0;
}

/**
 * io_zcrx_setup_xdp_mapping - Setup XDP mapping for zcrx region
 * @ifq: Zero-copy RX interface queue
 * @config: XDP mapping configuration
 */
int io_zcrx_setup_xdp_mapping(struct io_zcrx_ifq *ifq,
                               struct io_zcrx_xdp_config *config)
{
    struct io_zcrx_xdp_mapping *mapping;
    struct io_zcrx_area *area;
    int ret = 0;
    int i;
    
    if (!ifq || !ifq->area || !config)
        return -EINVAL;
        
    area = ifq->area;
    
    /* Allocate mapping structure */
    mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
    if (!mapping)
        return -ENOMEM;
        
    mapping->zcrx_area = area;
    mapping->frame_count = area->nia.num_niovs;
    mapping->frame_size = config->frame_size ?: PAGE_SIZE;
    mapping->chunk_size = config->chunk_size ?: PAGE_SIZE;
    mapping->headroom = config->headroom ?: XDP_PACKET_HEADROOM;
    mapping->flags = config->flags;
    spin_lock_init(&mapping->lock);
    
    /* Allocate XDP frame array */
    mapping->xdp_frames = kcalloc(mapping->frame_count, 
                                  sizeof(struct xdp_frame *), GFP_KERNEL);
    if (!mapping->xdp_frames) {
        ret = -ENOMEM;
        goto err_free_mapping;
    }
    
    /* Initialize XDP frames from zcrx pages */
    for (i = 0; i < mapping->frame_count; i++) {
        struct net_iov *niov = &area->nia.niovs[i];
        struct page *page = io_zcrx_iov_page(niov);
        void *data;
        
        if (!page) {
            ret = -EINVAL;
            goto err_cleanup_frames;
        }
        
        data = page_address(page);
        if (!data) {
            ret = -ENOMEM;
            goto err_cleanup_frames;
        }
        
        /* Create XDP frame */
        mapping->xdp_frames[i] = kzalloc(sizeof(struct xdp_frame), GFP_KERNEL);
        if (!mapping->xdp_frames[i]) {
            ret = -ENOMEM;
            goto err_cleanup_frames;
        }
        
        mapping->xdp_frames[i]->data = data + mapping->headroom;
        mapping->xdp_frames[i]->len = 0; /* Will be set when packet arrives */
        mapping->xdp_frames[i]->headroom = mapping->headroom;
        mapping->xdp_frames[i]->frame_sz = mapping->frame_size;
        mapping->xdp_frames[i]->mem.type = MEM_TYPE_PAGE_POOL;
    }
    
    /* Store mapping in the interface queue */
    ifq->xdp_mapping = mapping;
    
    pr_info("io_uring: XDP mapping setup for zcrx region with %u frames\n",
            mapping->frame_count);
    
    return 0;
    
err_cleanup_frames:
    for (i = 0; i < mapping->frame_count; i++) {
        if (mapping->xdp_frames[i])
            kfree(mapping->xdp_frames[i]);
    }
    kfree(mapping->xdp_frames);
    
err_free_mapping:
    kfree(mapping);
    return ret;
}

/**
 * io_zcrx_teardown_xdp_mapping - Teardown XDP mapping
 * @ifq: Zero-copy RX interface queue
 */
void io_zcrx_teardown_xdp_mapping(struct io_zcrx_ifq *ifq)
{
    struct io_zcrx_xdp_mapping *mapping;
    int i;
    
    if (!ifq || !ifq->xdp_mapping)
        return;
        
    mapping = ifq->xdp_mapping;
    
    /* Cleanup XDP frames */
    if (mapping->xdp_frames) {
        for (i = 0; i < mapping->frame_count; i++) {
            if (mapping->xdp_frames[i])
                kfree(mapping->xdp_frames[i]);
        }
        kfree(mapping->xdp_frames);
    }
    
    /* Free mapping structure */
    kfree(mapping);
    ifq->xdp_mapping = NULL;
    
    pr_debug("io_uring: XDP mapping teardown completed\n");
}

/**
 * io_zcrx_xdp_redirect - Handle XDP redirect to zcrx region
 * @ifq: Zero-copy RX interface queue
 * @xdp: XDP buffer to redirect
 * @target_index: Target frame index in zcrx region
 */
int io_zcrx_xdp_redirect(struct io_zcrx_ifq *ifq, struct xdp_buff *xdp,
                         u32 target_index)
{
    struct io_zcrx_xdp_mapping *mapping;
    struct net_iov *target_niov;
    struct page *target_page;
    void *target_data;
    u32 data_len;
    
    if (!ifq || !ifq->xdp_mapping || !xdp)
        return -EINVAL;
        
    mapping = ifq->xdp_mapping;
    
    if (target_index >= mapping->frame_count)
        return -EINVAL;
        
    spin_lock(&mapping->lock);
    
    /* Get target net_iov */
    target_niov = &mapping->zcrx_area->nia.niovs[target_index];
    target_page = io_zcrx_iov_page(target_niov);
    target_data = page_address(target_page);
    
    if (!target_data) {
        spin_unlock(&mapping->lock);
        return -ENOMEM;
    }
    
    /* Copy packet data to target buffer */
    data_len = xdp->data_end - xdp->data;
    if (data_len > (PAGE_SIZE - mapping->headroom)) {
        spin_unlock(&mapping->lock);
        return -ENOSPC;
    }
    
    memcpy(target_data + mapping->headroom, xdp->data, data_len);
    
    /* Update target frame information */
    mapping->xdp_frames[target_index]->len = data_len;
    
    /* Take reference on target net_iov */
    io_zcrx_get_buf_uref(target_niov);
    
    spin_unlock(&mapping->lock);
    
    return 0;
}

/**
 * io_zcrx_get_xdp_frame - Get XDP frame by index
 * @ifq: Zero-copy RX interface queue
 * @index: Frame index
 */
struct xdp_frame *io_zcrx_get_xdp_frame(struct io_zcrx_ifq *ifq, u32 index)
{
    struct io_zcrx_xdp_mapping *mapping;
    
    if (!ifq || !ifq->xdp_mapping)
        return NULL;
        
    mapping = ifq->xdp_mapping;
    
    if (index >= mapping->frame_count)
        return NULL;
        
    return mapping->xdp_frames[index];
}

/**
 * io_zcrx_xdp_frame_to_skb - Convert XDP frame to sk_buff
 * @ifq: Zero-copy RX interface queue
 * @frame_index: Index of the XDP frame
 */
struct sk_buff *io_zcrx_xdp_frame_to_skb(struct io_zcrx_ifq *ifq, 
                                          u32 frame_index)
{
    struct io_zcrx_xdp_mapping *mapping;
    struct xdp_frame *frame;
    struct sk_buff *skb;
    struct net_iov *niov;
    
    if (!ifq || !ifq->xdp_mapping)
        return NULL;
        
    mapping = ifq->xdp_mapping;
    
    if (frame_index >= mapping->frame_count)
        return NULL;
        
    frame = mapping->xdp_frames[frame_index];
    if (!frame || !frame->len)
        return NULL;
        
    /* Get associated net_iov */
    niov = &mapping->zcrx_area->nia.niovs[frame_index];
    
    /* Allocate sk_buff */
    skb = napi_alloc_skb(NULL, frame->len);
    if (!skb)
        return NULL;
        
    /* Copy data from XDP frame to sk_buff */
    skb_put_data(skb, frame->data, frame->len);
    
    /* Set up sk_buff with zero-copy fragment */
    skb_add_rx_frag_netmem(skb, 0, net_iov_to_netmem(niov), 
                          0, frame->len, PAGE_SIZE);
    
    return skb;
}

EXPORT_SYMBOL_GPL(io_zcrx_to_xdp_buf);
EXPORT_SYMBOL_GPL(io_zcrx_xdp_buf_to_niov);
EXPORT_SYMBOL_GPL(io_zcrx_setup_xdp_mapping);
EXPORT_SYMBOL_GPL(io_zcrx_teardown_xdp_mapping);
EXPORT_SYMBOL_GPL(io_zcrx_xdp_redirect);
EXPORT_SYMBOL_GPL(io_zcrx_get_xdp_frame);
EXPORT_SYMBOL_GPL(io_zcrx_xdp_frame_to_skb); 
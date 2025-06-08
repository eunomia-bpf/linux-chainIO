// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2024 Linux Foundation. All rights reserved.
 * 
 * XDP integration for SoftRoCE driver
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/netdevice.h>

#include "rxe.h"
#include "rxe_xdp.h"
#include "rxe_loc.h"

/**
 * rxe_xdp_init - Initialize XDP support for RXE device
 * @rxe: RXE device
 */
int rxe_xdp_init(struct rxe_dev *rxe)
{
	struct rxe_xdp_state *xdp_state;
	
	xdp_state = kzalloc(sizeof(*xdp_state), GFP_KERNEL);
	if (!xdp_state)
		return -ENOMEM;
	
	spin_lock_init(&xdp_state->xdp_lock);
	xdp_state->xdp_enabled = false;
	xdp_state->xdp_prog = NULL;
	
	/* Initialize XDP RX queue info */
	xdp_rxq_info_unreg(&xdp_state->xdp_rxq);
	
	/* Initialize statistics */
	atomic64_set(&xdp_state->xdp_pass, 0);
	atomic64_set(&xdp_state->xdp_drop, 0);
	atomic64_set(&xdp_state->xdp_redirect, 0);
	atomic64_set(&xdp_state->xdp_tx, 0);
	
	rxe->xdp_state = xdp_state;
	
	rxe_dbg_dev(rxe, "XDP support initialized\n");
	return 0;
}

/**
 * rxe_xdp_cleanup - Cleanup XDP support for RXE device
 * @rxe: RXE device
 */
void rxe_xdp_cleanup(struct rxe_dev *rxe)
{
	struct rxe_xdp_state *xdp_state = rxe->xdp_state;
	
	if (!xdp_state)
		return;
	
	/* Remove XDP program if attached */
	rxe_xdp_setup(rxe, NULL);
	
	/* Cleanup XDP RX queue info */
	xdp_rxq_info_unreg(&xdp_state->xdp_rxq);
	
	kfree(xdp_state);
	rxe->xdp_state = NULL;
	
	rxe_dbg_dev(rxe, "XDP support cleaned up\n");
}

/**
 * rxe_xdp_setup - Setup or remove XDP program
 * @rxe: RXE device
 * @prog: BPF program to attach (NULL to remove)
 */
int rxe_xdp_setup(struct rxe_dev *rxe, struct bpf_prog *prog)
{
	struct rxe_xdp_state *xdp_state = rxe->xdp_state;
	struct bpf_prog *old_prog;
	unsigned long flags;
	int err = 0;
	
	if (!xdp_state)
		return -EINVAL;
	
	spin_lock_irqsave(&xdp_state->xdp_lock, flags);
	
	old_prog = rcu_dereference_protected(xdp_state->xdp_prog,
					     lockdep_is_held(&xdp_state->xdp_lock));
	
	if (prog) {
		/* Register XDP RX queue info if not already done */
		if (!xdp_rxq_info_is_reg(&xdp_state->xdp_rxq)) {
			err = xdp_rxq_info_reg(&xdp_state->xdp_rxq, rxe->ndev, 0, 0);
			if (err < 0) {
				spin_unlock_irqrestore(&xdp_state->xdp_lock, flags);
				rxe_err_dev(rxe, "Failed to register XDP RX queue info\n");
				return err;
			}
		}
		
		/* Install new XDP program */
		bpf_prog_inc(prog);
		rcu_assign_pointer(xdp_state->xdp_prog, prog);
		xdp_state->xdp_enabled = true;
		
		rxe_info_dev(rxe, "XDP program installed\n");
	} else {
		/* Remove XDP program */
		rcu_assign_pointer(xdp_state->xdp_prog, NULL);
		xdp_state->xdp_enabled = false;
		
		rxe_info_dev(rxe, "XDP program removed\n");
	}
	
	spin_unlock_irqrestore(&xdp_state->xdp_lock, flags);
	
	/* Release old program after RCU grace period */
	if (old_prog) {
		synchronize_rcu();
		bpf_prog_put(old_prog);
	}
	
	return 0;
}

/**
 * rxe_xdp_process_tx - Process outgoing packet with XDP
 * @qp: Queue pair
 * @skb: Socket buffer containing RDMA packet
 * 
 * This function clones the SKB for XDP processing in the TX path.
 * The original SKB is still sent to the network stack.
 */
int rxe_xdp_process_tx(struct rxe_qp *qp, struct sk_buff *skb)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_xdp_state *xdp_state = rxe->xdp_state;
	struct bpf_prog *xdp_prog;
	struct xdp_buff xdp;
	struct sk_buff *xdp_skb;
	u32 act;
	int ret = 0;
	
	if (!xdp_state || !xdp_state->xdp_enabled)
		return 0;
	
	rcu_read_lock();
	xdp_prog = rcu_dereference(xdp_state->xdp_prog);
	
	if (!xdp_prog) {
		rcu_read_unlock();
		return 0;
	}
	
	/* Clone the SKB for XDP processing */
	xdp_skb = skb_clone(skb, GFP_ATOMIC);
	if (!xdp_skb) {
		rcu_read_unlock();
		rxe_dbg_qp(qp, "Failed to clone SKB for XDP\n");
		return 0; /* Don't fail transmission */
	}
	
	/* Convert cloned SKB to xdp_buff */
	xdp_init_buff(&xdp, skb_end_offset(xdp_skb), &xdp_state->xdp_rxq);
	xdp_prepare_buff(&xdp, xdp_skb->head, 
			 skb_headroom(xdp_skb),
			 xdp_skb->len, false);
	
	/* Run XDP program on cloned packet */
	act = bpf_prog_run_xdp(xdp_prog, &xdp);
	
	switch (act) {
	case XDP_PASS:
		atomic64_inc(&xdp_state->xdp_pass);
		break;
	case XDP_DROP:
		atomic64_inc(&xdp_state->xdp_drop);
		break;
	case XDP_TX:
		atomic64_inc(&xdp_state->xdp_tx);
		/* For TX path, we just monitor, don't actually TX */
		break;
	case XDP_REDIRECT:
		atomic64_inc(&xdp_state->xdp_redirect);
		ret = xdp_do_redirect(rxe->ndev, &xdp, xdp_prog);
		if (ret)
			rxe_dbg_qp(qp, "XDP redirect failed: %d\n", ret);
		break;
	default:
		bpf_warn_invalid_xdp_action(rxe->ndev, xdp_prog, act);
		atomic64_inc(&xdp_state->xdp_drop);
		break;
	}
	
	/* Free the cloned SKB */
	kfree_skb(xdp_skb);
	
	rcu_read_unlock();
	
	/* Always return 0 to allow normal transmission */
	return 0;
}

/**
 * rxe_xdp_process_rx - Process incoming packet with XDP
 * @rxe: RXE device
 * @pskb: Pointer to socket buffer containing received packet
 * 
 * Returns:
 *  0 - packet should be processed normally
 *  1 - packet was consumed by XDP (dropped/redirected)
 */
int rxe_xdp_process_rx(struct rxe_dev *rxe, struct sk_buff **pskb)
{
	struct rxe_xdp_state *xdp_state = rxe->xdp_state;
	struct bpf_prog *xdp_prog;
	struct xdp_buff xdp;
	struct sk_buff *skb = *pskb;
	u32 act;
	int ret = 0;
	
	if (!xdp_state || !xdp_state->xdp_enabled)
		return 0;
	
	rcu_read_lock();
	xdp_prog = rcu_dereference(xdp_state->xdp_prog);
	
	if (!xdp_prog) {
		rcu_read_unlock();
		return 0;
	}
	
	/* Convert SKB to xdp_buff */
	xdp_init_buff(&xdp, skb_end_offset(skb), &xdp_state->xdp_rxq);
	xdp_prepare_buff(&xdp, skb->head,
			 skb_headroom(skb),
			 skb->len, false);
	
	/* Run XDP program */
	act = bpf_prog_run_xdp(xdp_prog, &xdp);
	
	switch (act) {
	case XDP_PASS:
		atomic64_inc(&xdp_state->xdp_pass);
		/* Update SKB if XDP modified the packet */
		skb->data = xdp.data;
		skb->len = xdp.data_end - xdp.data;
		skb_set_tail_pointer(skb, skb->len);
		break;
		
	case XDP_DROP:
		atomic64_inc(&xdp_state->xdp_drop);
		kfree_skb(skb);
		*pskb = NULL;
		ret = 1; /* Packet consumed */
		break;
		
	case XDP_TX:
		atomic64_inc(&xdp_state->xdp_tx);
		/* For RoCE, TX means send back through RDMA path */
		kfree_skb(skb);
		*pskb = NULL;
		ret = 1; /* Packet consumed */
		break;
		
	case XDP_REDIRECT:
		atomic64_inc(&xdp_state->xdp_redirect);
		ret = xdp_do_redirect(rxe->ndev, &xdp, xdp_prog);
		if (ret) {
			rxe_dbg_dev(rxe, "XDP redirect failed: %d\n", ret);
			kfree_skb(skb);
		}
		*pskb = NULL;
		ret = 1; /* Packet consumed */
		break;
		
	default:
		bpf_warn_invalid_xdp_action(rxe->ndev, xdp_prog, act);
		atomic64_inc(&xdp_state->xdp_drop);
		kfree_skb(skb);
		*pskb = NULL;
		ret = 1; /* Packet consumed */
		break;
	}
	
	rcu_read_unlock();
	
	return ret;
}

/**
 * rxe_xdp_netdev_event - Handle network device events for XDP
 * @rxe: RXE device
 * @event: Network device event
 */
int rxe_xdp_netdev_event(struct rxe_dev *rxe, unsigned long event)
{
	struct net_device *ndev = rxe->ndev;
	struct bpf_prog *xdp_prog;
	int ret = 0;
	
	switch (event) {
	case NETDEV_CHANGE:
		/* Check if XDP program is attached to the network device */
		rcu_read_lock();
		xdp_prog = rcu_dereference(ndev->xdp_prog);
		if (xdp_prog) {
			/* XDP program detected on network device */
			rxe_info_dev(rxe, "XDP program detected on %s, initializing RXE XDP support\n",
				     ndev->name);
			
			/* Initialize XDP if not already done */
			if (!rxe->xdp_state) {
				rcu_read_unlock();
				ret = rxe_xdp_init(rxe);
				if (ret) {
					rxe_err_dev(rxe, "Failed to initialize XDP support\n");
					return ret;
				}
				rcu_read_lock();
				xdp_prog = rcu_dereference(ndev->xdp_prog);
			}
			
			/* Setup XDP program in RXE */
			if (xdp_prog && rxe->xdp_state) {
				rcu_read_unlock();
				ret = rxe_xdp_setup(rxe, xdp_prog);
				if (ret)
					rxe_err_dev(rxe, "Failed to setup XDP program\n");
				return ret;
			}
		}
		rcu_read_unlock();
		break;
		
	case NETDEV_DOWN:
		/* Remove XDP program when device goes down */
		if (rxe->xdp_state)
			rxe_xdp_setup(rxe, NULL);
		break;
		
	default:
		break;
	}
	
	return ret;
}
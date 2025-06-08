/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2024 Linux Foundation. All rights reserved.
 */

#ifndef RXE_XDP_H
#define RXE_XDP_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/atomic.h>

struct rxe_dev;
struct rxe_qp;

/* XDP integration state for RXE device */
struct rxe_xdp_state {
	struct bpf_prog __rcu *xdp_prog;
	spinlock_t xdp_lock;
	bool xdp_enabled;
	
	/* XDP RX queue info */
	struct xdp_rxq_info xdp_rxq;
	
	/* Statistics */
	atomic64_t xdp_pass;
	atomic64_t xdp_drop;
	atomic64_t xdp_redirect;
	atomic64_t xdp_tx;
};

/* XDP initialization and cleanup */
int rxe_xdp_init(struct rxe_dev *rxe);
void rxe_xdp_cleanup(struct rxe_dev *rxe);

/* XDP program attachment */
int rxe_xdp_setup(struct rxe_dev *rxe, struct bpf_prog *prog);

/* XDP packet processing */
int rxe_xdp_process_tx(struct rxe_qp *qp, struct sk_buff *skb);
int rxe_xdp_process_rx(struct rxe_dev *rxe, struct sk_buff **pskb);

/* Network device event handler */
int rxe_xdp_netdev_event(struct rxe_dev *rxe, unsigned long event);

#endif /* RXE_XDP_H */
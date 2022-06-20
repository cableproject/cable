/* SPDX-License-Identifier: GPL-2.0 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/pkt_cls.h>
#include "bpf_helpers.h"
#include "maps.h"

#ifndef __EDT_H_
#define __EDT_H_


#define __ctx_buff		__sk_buff
#define __ctx_is		__ctx_skb


#define CTX_ACT_OK		0
#define CTX_ACT_DROP		2
#define CTX_ACT_TX		7


struct edt_id {
	__u64		id;
};

struct edt_info {
	__u64		bps;
	__u64		t_last;
	__u64		t_horizon_drop;
	__u64		pad[4];
};


#ifndef __READ_ONCE
# define __READ_ONCE(X)		(*(volatile typeof(X) *)&X)
#endif

#ifndef __WRITE_ONCE
# define __WRITE_ONCE(X, V)	(*(volatile typeof(X) *)&X) = (V)
#endif

#ifndef barrier
# define barrier()		asm volatile("": : :"memory")
#endif

static __always_inline void bpf_barrier(void)
{
	barrier();
}

#ifndef READ_ONCE
# define READ_ONCE(X)						\
			({ typeof(X) __val = __READ_ONCE(X);	\
			   bpf_barrier();			\
			   __val; })
#endif

#ifndef WRITE_ONCE
# define WRITE_ONCE(X, V)					\
				({ typeof(X) __val = (V);	\
				   __WRITE_ONCE(X, __val);	\
				   bpf_barrier();		\
				   __val; })
#endif


static __always_inline void edt_set_aggregate(struct __ctx_buff *ctx,
					      __u32 aggregate)
{
	ctx->queue_mapping = aggregate;
}

static __always_inline __u32 edt_get_aggregate(struct __ctx_buff *ctx)
{
	__u32 aggregate = ctx->queue_mapping;
	ctx->queue_mapping = 0;

	return aggregate;
}


static __always_inline __u32
ctx_wire_len(const struct __sk_buff *ctx)
{
	return ctx->wire_len;
}

static __always_inline void *ctx_data(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data;
}

static __always_inline void *ctx_data_meta(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data_meta;
}

static __always_inline void *ctx_data_end(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data_end;
}

static __always_inline bool validate_ethertype(struct __ctx_buff *ctx,
					       __u16 *proto)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = data;

	if (data + ETH_HLEN > data_end)
		return false;
	*proto = eth->h_proto;
	if (bpf_ntohs(*proto) < ETH_P_802_3_MIN)
		return false;
	return true;
}


#endif /* __EDT_H_ */

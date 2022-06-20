#define KBUILD_MODNAME "qos"
#include <linux/pkt_cls.h>
#include "bpf_endian.h"
#include "logger.h"
#include "edt.h"

#define PIN_GLOBAL_NS		2
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
//flow->src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
//flow->dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

/* compiler workaround */
#define _htonl __builtin_bswap32

struct bpf_elf_map {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};


struct bpf_elf_map SEC("maps") m_qers = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32), // teid
	.value_size  = sizeof(struct edt),
	.pinning = PIN_GLOBAL_NS, // PIN_GLOBAL_NS
	.max_elem = 60,
};

						   
static __always_inline int edt_sched_departure(struct __ctx_buff *ctx)
{
	__u64 delay, now, t, t_next;
	struct edt_id aggregate;
	struct edt_info *info;
	__u16 proto;
    __u32 k_qos = 0x00;
    int err;

    if (!validate_ethertype(ctx, &proto)){
        return CTX_ACT_OK;
    }

    if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6)){
	    return CTX_ACT_OK;
	}

    k_qos = _htonl(load_word(ctx, IP_SRC_OFF));; //src ip "1.1.1.3";
    if (!k_qos){
        return CTX_ACT_DROP;
    }

	aggregate.id = edt_get_aggregate(ctx);
	if (!aggregate.id)
		return CTX_ACT_OK;

    info = bpf_map_lookup_elem(&m_qers, &k_qos);
    if (!info){
	   return CTX_ACT_DROP;
    }

	now = bpf_ktime_get_ns();
	t = ctx->tstamp;
    if (t < now)
    	t = now;

	delay = ((__u64)ctx_wire_len(ctx)) * NSEC_PER_SEC / info->bps;

    t_next = READ_ONCE(info->t_last) + delay;

	if (t_next <= t) {
		WRITE_ONCE(info->t_last, t);
		return CTX_ACT_OK;
	}
	
	if (t_next - now >= info->t_horizon_drop){
		return CTX_ACT_DROP;
    }

    WRITE_ONCE(info->t_last, t_next);
	ctx->tstamp = t_next;
	return CTX_ACT_OK;
}


SEC("qos")
int to_netdev(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
    bpf_debug("===> 1 tc qos\n");
	ret = edt_sched_departure(ctx);
	/* No send_drop_notify_error() here given we're rate-limiting. */
	if (ret == CTX_ACT_DROP) {
		return ret;
	}
    return ret;
}


char _license[] SEC("license") = "GPL";

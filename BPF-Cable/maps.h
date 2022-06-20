#ifndef __MAPS_H__
#define __MAPS_H__
#include "bpf_helpers.h"
#include "upf.h"

struct pdrs{
    __u8 src_mac[ETH_ALEN];
    __u8 des_mac[ETH_ALEN];
    __u32 src_ip;
    __u32 des_ip;
    __u8 qfi;
};


struct psa_gtpu{
    __u8 src_mac[ETH_ALEN];
    __u8 des_mac[ETH_ALEN];
    __u32 src_ip;
    __u32 des_ip;
    teid_t teid;
};

struct edt {
	__u64 bps;
	__u64 t_last;
	__u64 t_horizon_drop;
};

struct bpf_map_def SEC("maps") m_teid_pdrs = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(teid_t),
	.value_size  = sizeof(struct pdrs),
	.max_entries = 60,
};

struct bpf_map_def SEC("maps") m_psa_gtpu = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(teid_t),
	.value_size  = sizeof(struct psa_gtpu),
	.max_entries = 60,
};
struct xdpkey
{
  u32 type;
  u64 ip;
  u64 teid;
};

struct bpf_map_def SEC("maps") gtp_monitor_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct xdpkey),
    .value_size = sizeof(long),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
};
#endif // __MAPS_H__

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/string.h>
#include "bpf_helpers.h"
#include "upf.h"


/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader.
 * You can either use the helper header file below
 * so that you don't need to defind it yourself:
 * #include <bpf/bpf_helpers.h> 
 */
#define PFCP_PORT 8805u
#define SEC(NAME) __attribute__((section(NAME), used))
#define bpf_printk(fmt, ...)                       \
	({                                             \
		char ____fmt[] = fmt;                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), \
						 ##__VA_ARGS__);           \
	})

struct xdpkey
{
    u32 type;
    u64 ip;
    u64 teid;
};

//#define XDP_UNKNOWN	XDP_REDIRECT + 1
struct bpf_map_def SEC("maps") gtp_monitor_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct xdpkey),
    .value_size = sizeof(long),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
};

// struct bpf_map_def SEC("maps") gtp_monitor_map = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(int),
//     .value_size = sizeof(long),
//     .max_entries = 100,
// 	.map_flags = BPF_F_NO_PREALLOC,
// };
enum { GTP_U = 0,
       GTP_C = 1,
       GTP = 2,
       UNKNOW = 3
};
static inline struct xdpkey *calGtpKey(struct udphdr *udph, void *data_end, struct xdpkey *key)
{
    struct gtpuhdr *gtp = (struct gtpuhdr *)(udph + 1);
    if ((void *)gtp + sizeof(*gtp) > data_end)
    {
        bpf_printk("Invalid gtp packet\n");
        return key;
    }
    struct iphdr *ip = (struct iphdr *)(gtp + 1);
    if ((void *)ip + sizeof(*ip) > data_end)
    {
        bpf_printk("Invalid gtp_ip packet\n");
        return key;
    }
    u64 teid = htonl(gtp->teid);
    u64 src_ip = htonl(ip->saddr);
    bpf_printk("GTP GPDU teid %d and ip %d \n", teid, src_ip);
    key->ip=src_ip;
    key->teid=teid;
    return key;
}
static inline void collection_process(struct xdpkey *key)
{
    bpf_printk("collection_process\n");
    long *cnt;
    cnt = bpf_map_lookup_elem(&gtp_monitor_map, key);
    long value = 1;
    if (!cnt)
    {
        bpf_printk("cut==null\n");
        bpf_map_update_elem(&gtp_monitor_map, key, &value, BPF_ANY);
        return;
    }

    *cnt += 1;
    bpf_printk("update map ip: %lld;teid: %lld; value: %ld \n", key->ip, key->teid, *cnt);
}

// entrance for this program
SEC("xdp")
int xdp_monitor(struct xdp_md *ctx)
{
    bpf_printk("enter monitor\n");
    int ipsize = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    ipsize = sizeof(*eth);
    ip = data + ipsize;

    ipsize += sizeof(struct iphdr);
    if (data + ipsize > data_end)
    {
        bpf_printk("data too long\n");
        return XDP_PASS;
    }


    bpf_printk("protocol: %d \n", ip->protocol);
    if (ip->protocol == IPPROTO_UDP)
    {
        bpf_printk("enter udp \n");
        struct udphdr *udph = (struct udphdr *)(ip + 1);
        if ((void *)udph + sizeof(*udph) > data_end)
        {
            bpf_printk("Invalid UDP packet\n");
            return XDP_PASS;
        }
        u_short port = ntohs(udph->dest);
        bpf_printk("UDP port %d\n", port);
        if (port == PFCP_PORT)
        {
            struct xdpkey key = {GTP_C,0,0};
            collection_process(&key);
            return XDP_PASS;
        }
        if (port == GTP_UDP_PORT)
        {
            struct xdpkey default_key = {GTP_U,0,0};
            struct xdpkey *key = calGtpKey(udph, data_end,&default_key);
            collection_process(&default_key);
            return XDP_PASS;
        }
    }
    struct xdpkey key = {UNKNOW,0,0};
    collection_process(&key);

    return XDP_PASS;
}

// for bpf verifier
char _license[] SEC("license") = "GPL";

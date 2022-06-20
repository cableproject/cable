
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
//#define XDP_UNKNOWN	XDP_REDIRECT + 1
struct bpf_map_def SEC("maps") down_monitor_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
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
enum
{
    GTP_U = 0,
    GTP_C = 1,
    GTP = 2,
    UNKNOW = 3
};
static inline u32 calGtpKey(struct iphdr *ip,void *data_end){
       
        if ((void *)ip + sizeof(*ip) > data_end)
        {
            bpf_printk("Invalid gtp_ip packet\n");
            return GTP_U;
        }
        u32 dst_ip = htonl(ip->daddr);
        bpf_printk("GTP GPDUip %d \n",dst_ip);
        return dst_ip;
}
static inline void collection_process(u32 key)
{
    bpf_printk("collection_process\n");
    long *cnt;
    cnt = bpf_map_lookup_elem(&down_monitor_map, &key);
    long value=1;
    if (!cnt){
        bpf_printk("cut==null\n");
        bpf_map_update_elem(&down_monitor_map, &key, &value, BPF_ANY);
        return;
    }
		
	*cnt += 1;
    bpf_printk("update map key: %d; value: %ld \n", key, *cnt);
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

    // if (ip->protocol == IPPROTO_TCP)
    // {
    //     struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    //     ipsize += sizeof(struct tcphdr);
    //     if (data + ipsize > data_end)
    //     {
    //         bpf_printk("Invalid TCP packet\n");
    //         return XDP_PASS;
    //     }
    // }
    bpf_printk("protocol: %d \n",ip->protocol );
    // if (ip->protocol == IPPROTO_UDP)
    // {
    //     bpf_printk("enter udp \n");
    //     struct udphdr *udph = (struct udphdr *)(ip + 1);
    //     if ((void *)udph + sizeof(*udph) > data_end)
    //     {
    //         bpf_printk("Invalid UDP packet\n");
    //         return XDP_PASS;
    //     }
    //     u_short port = ntohs(udph->dest);
    //     bpf_printk("UDP port %d\n",port);
    //     if (port ==PFCP_PORT){
    //         collection_process(GTP_C);
    //         return XDP_PASS;

    //     }
    //     if(port == GTP_U){
    //         u32 key = calGtpKey(udph,data_end);
    //         collection_process(key);
    //         return XDP_PASS;
    //     }
    // }
    u32 key = calGtpKey(ip,data_end);
    collection_process(key);

    return XDP_PASS;
}

// for bpf verifier
char _license[] SEC("license") = "GPL";

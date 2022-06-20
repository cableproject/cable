#define KBUILD_MODNAME "upf"
#include <uapi/linux/bpf.h>
#include <linux/byteorder/generic.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include "upf.h"
#include "logger.h"
#include "maps.h"
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/string.h>
#include "bpf_helpers.h"

#define PFCP_PORT 8805u
#define SEC(NAME) __attribute__((section(NAME), used))


# define downlink 10
# define uplink 11

enum
{
  GTP_U = 0,
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

  key->ip = src_ip;
  key->teid = teid;
  return key;
}
static inline void collection_process(struct xdpkey *key)
{

  long *cnt;
  cnt = bpf_map_lookup_elem(&gtp_monitor_map, key);
  long value = 1;
  if (!cnt)
  {

    bpf_map_update_elem(&gtp_monitor_map, key, &value, BPF_ANY);
    return;
  }

  *cnt += 1;

}

static u32 pfcp_pdr_match_attribute(pfcp_pdr_t *p_pdr, u32 ueIp)
{
  if( p_pdr->ueIp != ueIp){
        bpf_debug("Not match:\n");
        return 1;
    }
  bpf_debug("All atrributes were matched!!\n");
  return 0;
}

static u32 gtpu_decap(struct xdp_md *ctx, struct gtpuhdr *gtpuh)
{
  int delta;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *eth_cpy = (void *)(long)ctx->data + 36;
  if (data + 50 > data_end)
  {
    bpf_debug("gtpu_decap:Invalid packet\n");
    return XDP_ABORTED;
  }
  delta = 36;
  __builtin_memcpy(eth_cpy, data, sizeof(struct ethhdr));
  if (0 == bpf_xdp_adjust_head(ctx, delta))
  {
    return XDP_PASS;
  }
  else
  {
    return XDP_DROP;
  }
}

static u32 pdr_lookup_uplink(struct xdp_md *ctx, struct gtpuhdr *gtpuh)
{
  pfcp_pdr_t *p_pdr;
  uint32_t teid = 0;
  uint16_t message_length =0;

  void *data_end = (void *)(long)ctx->data_end;

  if ((u8 *)gtpuh + GTPV1U_MSG_HEADER_MIN_SIZE > data_end)
  {
    bpf_debug("Invalid UDP packet\n");
    return XDP_ABORTED;
  }

  u8 *p_data = (u8 *)gtpuh + GTPV1U_MSG_HEADER_MIN_SIZE;
  if (p_data + sizeof(struct iphdr) > data_end)
  {
    return XDP_ABORTED;
  }

  teid = gtpuh->teid;
  message_length = gtpuh->message_length;

  teid = htonl(0x01);
  p_pdr = bpf_map_lookup_elem(&m_teid_pdrs, &teid);
  if (!p_pdr)
  {
    bpf_debug("Error GTP GPDU teid %x with IPv4 payload received, %d, size %d\n", ntohl(teid), ntohl(message_length), sizeof(u32));
    return XDP_ABORTED;
  }
  
  return uplink;
}

static u32 is_gtp(struct xdp_md *ctx, struct udphdr *udph)
{
  void *data_end = (void *)(long)ctx->data_end;
  struct gtpuhdr *gtpuh = (struct gtpuhdr *)(udph + 1);

  u32 dport;

  /* Hint: +1 is sizeof(struct udphdr) */
  if ((void *)udph + sizeof(*udph) > data_end)
  {
    bpf_debug("Invalid UDP packet\n");
    return XDP_ABORTED;
  }

  bpf_debug("===>5. UDP packet validated\n");
  dport = htons(udph->dest);

  switch (dport)
  {
      case GTP_UDP_PORT:
        if (gtpuh->message_type == GTPU_G_PDU)
        {
        return XDP_REDIRECT;
        }
        return XDP_PASS;
      default:
        bpf_debug("GTP port %lu not valid\n", dport);
        return XDP_PASS;
      }
}

static u32 redirect_to_ue(struct xdp_md *ctx, struct ethhdr *ethh)
{
    struct iphdr *p_iph = (struct iphdr *)((void *)ethh + sizeof(*ethh));
    struct udphdr *udph = (struct udphdr *)(p_iph + 1);
    struct gtpuhdr *gtpuh = (struct gtpuhdr *)(udph + 1);
    void *data_end = (void *)(long)ctx->data_end;

    u32 dport;
    /* Hint: +1 is sizeof(struct udphdr) */
    if ((void *)udph + sizeof(*udph) > data_end)
    {
        bpf_debug("Invalid UDP packet\n");
        return XDP_ABORTED;
    }

    dport = htons(udph->dest);
    if(dport != GTP_UDP_PORT)
    {
        bpf_debug("Invalid GTPU packet by udp port\n");
        return XDP_ABORTED;
    }

    if ((void *)gtpuh + sizeof(*gtpuh) > data_end)
    {
        bpf_debug("Invalid GTPU packet by gtp mess\n");
        return XDP_ABORTED;
    }

    if (gtpuh->message_type != GTPU_G_PDU)
    {
        bpf_debug("Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type, GTPU_G_PDU);
        return XDP_ABORTED;
    }

    u32 csum = 0;
    u32 teid = htonl(0x01);

    __u8 des_mac[ETH_ALEN];
    __u8 src_mac[ETH_ALEN];

    des_mac[0] = 0x52;
    des_mac[1] = 0x54;
    des_mac[2] = 0x00;
    des_mac[3] = 0xba;
    des_mac[4] = 0x6e;
    des_mac[5] = 0x6f;

    src_mac[0] = 0x52;
    src_mac[1] = 0x54;
    src_mac[2] = 0x00;
    src_mac[3] = 0x44;
    src_mac[4] = 0x09;
    src_mac[5] = 0x86;

    __builtin_memcpy(ethh->h_source, src_mac, ETH_ALEN);
    __builtin_memcpy(ethh->h_dest, des_mac, ETH_ALEN);

    p_iph->tos = 0;
    p_iph->check = 0;
    csum = 0;
    ipv4_csum(p_iph, sizeof(struct iphdr), &csum);

    gtpuh->teid = teid;

    return XDP_TX;
}

static u32 pdr_lookup_downlink(struct xdp_md *ctx, struct iphdr *iph, unsigned int ran_ip)
{
    return downlink;
}


static __always_inline void set_ethhdr(struct ethhdr *new_eth,
                                       const struct ethhdr *old_eth,
                                       __be16 h_proto)
{
  __u8 h_tmp_src[ETH_ALEN];
  __u8 h_tmp_dst[ETH_ALEN];

  __builtin_memcpy(h_tmp_src, old_eth->h_source, ETH_ALEN);
  __builtin_memcpy(h_tmp_dst, old_eth->h_dest, ETH_ALEN);

  __builtin_memcpy(new_eth->h_dest, h_tmp_src, ETH_ALEN);
  __builtin_memcpy(new_eth->h_source, h_tmp_dst, ETH_ALEN);

  new_eth->h_proto = h_proto;
}

static u32 gtp_handle(struct xdp_md *ctx, struct gtpuhdr *gtpuh)
{
  void *data_end = (void *)(long)ctx->data_end;
  if ((void *)gtpuh + sizeof(*gtpuh) > data_end)
  {
    bpf_debug("Invalid GTPU packet\n");
    return XDP_ABORTED;
  }

  if (gtpuh->message_type != GTPU_G_PDU)
  {
    bpf_debug("Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type, GTPU_G_PDU);
    return XDP_ABORTED;
  }
  return pdr_lookup_uplink(ctx, gtpuh);
}


static u32 udp_handle(struct xdp_md *ctx, struct udphdr *udph)
{
  void *data_end = (void *)(long)ctx->data_end;
  u32 dport;

  /* Hint: +1 is sizeof(struct udphdr) */
  if ((void *)udph + sizeof(*udph) > data_end)
  {
    bpf_debug("Invalid UDP packet\n");
    return XDP_ABORTED;
  }

  dport = htons(udph->dest);
  u_short port = ntohs(udph->dest);

  if (port == PFCP_PORT)
  {
    struct xdpkey key = {GTP_C, 0, 0};
    collection_process(&key);
  }
  if (port == GTP_UDP_PORT)
  {
    struct xdpkey default_key = {GTP_U, 0, 0};
    struct xdpkey *key = calGtpKey(udph, data_end, &default_key);
    collection_process(&default_key);
  }

  switch (dport)
  {
  case PFCP_PORT:
  case GTP_UDP_PORT:
    return gtp_handle(ctx, (struct gtpuhdr *)(udph + 1));
  default:
    bpf_debug("GTP port %lu not valid\n", dport);
    return XDP_PASS;
  }
}

static u32 match_ueip(u32 ip, u32 ran_ip)
{
  if( ran_ip == ip){
      return 0;
  }else{
      return 1;
  }
}

static u32 ipv4_handle(struct xdp_md *ctx, struct iphdr *iph)
{
  void *data_end = (void *)(long)ctx->data_end;
  u32 ip_saddr;
  u8 result;
  u32 ran_ip = htonl(335544325); //"20.0.0.5";

  if ((void *)iph + sizeof(*iph) > data_end)
  {
    bpf_debug("Invalid IPv4 packet\n");
    return XDP_ABORTED;
  }
  ip_saddr = iph->saddr;


  if (match_ueip(ip_saddr, ran_ip))
  {
    return pdr_lookup_downlink(ctx,iph, ran_ip);
  }
  else
  {
    switch (iph->protocol)
    {
    case IPPROTO_UDP:
      result = udp_handle(ctx, (struct udphdr *)(iph + 1));
      return result;
      break;
    default:
      return XDP_PASS;
    }
  }
  return XDP_PASS;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}

static u32 rediect_to_psa_upf(struct xdp_md *ctx, struct ethhdr *ethh)
{
    struct iphdr *p_iph = (struct iphdr *)((void *)ethh + sizeof(*ethh));
    struct udphdr *p_udp = (struct udphdr *)(p_iph + 1);
    struct gtpuhdr *gtpuh = (struct gtpuhdr *)(p_udp + 1);

    struct psa_gtpu *psa_upf_gtpu;

    u32 teid = gtpuh->teid;
    u32 csum = 0;

    psa_upf_gtpu = bpf_map_lookup_elem(&m_psa_gtpu, &teid);
    if (!psa_upf_gtpu)
    {
        bpf_debug("Error - no find psa_upf_gtpu.");
        return XDP_ABORTED;
    }

    __builtin_memcpy(ethh->h_dest, psa_upf_gtpu->des_mac, ETH_ALEN);
    __builtin_memcpy(ethh->h_source, psa_upf_gtpu->src_mac, ETH_ALEN);

    p_iph->daddr = psa_upf_gtpu->des_ip;
    p_iph->saddr = psa_upf_gtpu->src_ip;

    ipv4_csum(p_udp, sizeof(struct udphdr), &csum);
	p_udp->check = csum;

    p_iph->tos = 0;
    p_iph->check = 0;
    csum = 0;
    ipv4_csum(p_iph, sizeof(struct iphdr), &csum);

    gtpuh->teid = psa_upf_gtpu->teid;
    return XDP_TX;

}


static u32 eth_handle(struct xdp_md *ctx, struct ethhdr *ethh)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth_head = data;
  u16 eth_type;
  u64 offset;
  struct vlan_hdr *vlan_hdr;
  u8 result;
  
  offset = sizeof(*ethh);
  if ((void *)ethh + offset > data_end)
  {
    bpf_debug("Cannot parse:%llu", offset);
    return XDP_DROP;
  }

  eth_type = htons(ethh->h_proto);
  switch (eth_type)
  {
  case ETH_P_IP:
    result = ipv4_handle(ctx, (struct iphdr *)((void *)ethh + offset));

    if (uplink == result)
    {
      result = rediect_to_psa_upf(ctx, ethh);
    }
    else if(downlink == result)
    {
      result = redirect_to_ue(ctx, ethh);
    }
    return result;
    break;
  case ETH_P_IPV6:
  case ETH_P_ARP:
  default:
    bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n", offset, eth_type);
    return XDP_PASS;
  }
  return XDP_PASS;
}

SEC("xdp")
int upf_input(struct xdp_md *ctx)
{
  __u64 now = 0;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  return eth_handle(ctx, eth);
}

SEC("tc_redirect")
int gtp_redirect(struct __sk_buff *skb)
{
  bpf_debug("tc_redirect_get_gtp");
  return bpf_redirect(5, 0);
}

char _license[] SEC("license") = "GPL";
